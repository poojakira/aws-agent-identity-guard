"""
aws_agent_identity_guard/scanner.py
────────────────────────────────────────────────────────────────────────────────
Static IAM policy linter targeting AI agent roles on AWS.

Catches overly-permissive patterns that are common when teams quickly grant
Bedrock, SageMaker, Lambda, SSM, or ECS permissions to autonomous AI agents.
Each rule maps to a real privilege-escalation or data-exfiltration vector
observed in production agent deployments.

Rule categories:
  AIG001-AIG007  Identity policy rules (original set)
  AIG008-AIG018  Agent-specific escalation and blast-radius rules (expanded)
  AIG-TP001-003  Trust policy rules
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from typing import Any


# ─── Action pattern sets ──────────────────────────────────────────────────────
# Each set represents a category of risk. When an agent policy grants actions
# from these sets without proper scoping, we flag it.

PRIVILEGE_ACTIONS = {
    "iam:CreateRole",
    "iam:PutRolePolicy",
    "iam:AttachRolePolicy",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "sts:AssumeRole",
    "iam:DeleteRolePolicy",
    "iam:DetachRolePolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:PutUserPolicy",
    "iam:AttachUserPolicy",
    "iam:AddUserToGroup",
}

TOOL_EXECUTION_PATTERNS = (
    "lambda:InvokeFunction",
    "lambda:InvokeAsync",
    "ssm:SendCommand",
    "ssm:StartSession",
    "ssm:StartAutomationExecution",
    "states:StartExecution",
    "states:StartSyncExecution",
    "ecs:RunTask",
    "ecs:StartTask",
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock-agent:InvokeAgent",
    "bedrock-agent-runtime:InvokeAgent",
    "bedrock-agent-runtime:Retrieve",
    "bedrock-agent-runtime:RetrieveAndGenerate",
    "sagemaker-runtime:InvokeEndpoint",
    "sagemaker-runtime:InvokeEndpointAsync",
    "execute-api:Invoke",
)

SENSITIVE_DATA_PATTERNS = (
    "secretsmanager:GetSecretValue",
    "secretsmanager:ListSecrets",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "s3:GetObject",
    "s3:ListBucket",
    "logs:GetLogEvents",
    "logs:FilterLogEvents",
    "dynamodb:GetItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "rds-data:ExecuteStatement",
    "rds-data:BatchExecuteStatement",
)

# Bedrock-specific actions that let an agent modify its own capabilities
BEDROCK_CONTROL_PLANE = (
    "bedrock:CreateAgent",
    "bedrock:UpdateAgent",
    "bedrock:CreateAgentActionGroup",
    "bedrock:UpdateAgentActionGroup",
    "bedrock:CreateKnowledgeBase",
    "bedrock:UpdateKnowledgeBase",
    "bedrock:AssociateAgentKnowledgeBase",
    "bedrock:CreateGuardrail",
    "bedrock:UpdateGuardrail",
    "bedrock:DeleteGuardrail",
    "bedrock:CreateModelCustomizationJob",
    "bedrock:CreateProvisionedModelThroughput",
)

# SageMaker actions that allow model deployment or training modifications
SAGEMAKER_CONTROL_PLANE = (
    "sagemaker:CreateEndpoint",
    "sagemaker:UpdateEndpoint",
    "sagemaker:CreateEndpointConfig",
    "sagemaker:CreateModel",
    "sagemaker:CreateTrainingJob",
    "sagemaker:CreateProcessingJob",
    "sagemaker:CreateNotebookInstance",
    "sagemaker:StartNotebookInstance",
    "sagemaker:CreatePresignedNotebookInstanceUrl",
)

# Actions that allow network egress or establishing external connections
NETWORK_EGRESS_PATTERNS = (
    "ec2:CreateNetworkInterface",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:ModifyNetworkInterfaceAttribute",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionConfiguration",
    "ecs:CreateService",
    "ecs:UpdateService",
)

# Actions that allow log/trail tampering — an agent covering its tracks
ANTI_FORENSICS_PATTERNS = (
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
    "logs:DeleteLogGroup",
    "logs:DeleteLogStream",
    "logs:PutRetentionPolicy",
    "config:StopConfigurationRecorder",
    "config:DeleteDeliveryChannel",
    "guardduty:DeleteDetector",
    "guardduty:UpdateDetector",
    "securityhub:DisableSecurityHub",
    "access-analyzer:DeleteAnalyzer",
)


@dataclass(frozen=True)
class Finding:
    """A single policy lint finding with severity and fix guidance."""

    rule_id: str
    severity: str
    message: str
    remediation: str
    statement_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _as_list(value: Any) -> list[str]:
    """Normalize a policy value (string, list, or None) into a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _matches_any(action: str, patterns: set[str] | tuple[str, ...]) -> bool:
    """Check if an action string matches any pattern (case-insensitive).

    Uses exact match for literal strings (like 'iam:CreateRole') and
    fnmatch for patterns containing wildcards (like 'bedrock:Invoke*').
    The intent is to match the policy ACTION value against our known-bad
    patterns — NOT to expand wildcards in the action itself.
    """
    action_lower = action.lower()
    for pattern in patterns:
        pattern_lower = pattern.lower()
        if "*" in pattern_lower or "?" in pattern_lower:
            if fnmatchcase(action_lower, pattern_lower):
                return True
        else:
            if action_lower == pattern_lower:
                return True
    return False


def _statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract Statement list from a policy document, normalizing edge cases."""
    statement = document.get("Statement", [])
    if isinstance(statement, dict):
        return [statement]
    if isinstance(statement, list):
        return [s for s in statement if isinstance(s, dict)]
    return []


def _count_actions(actions: list[str]) -> int:
    """Count distinct non-wildcard actions in a statement for blast-radius check."""
    return len([a for a in actions if a != "*" and not a.endswith(":*")])


def scan_policy_document(document: dict[str, Any]) -> list[Finding]:
    """Scan an IAM identity policy for agent-specific security risks.

    Returns a list of findings sorted by severity. Each finding includes
    a rule ID, severity level, human-readable message, and specific
    remediation guidance.

    Parameters
    ----------
    document : dict
        A parsed IAM policy document (the JSON object with Version and Statement).

    Returns
    -------
    list[Finding]
        All findings detected. Empty list means the policy passes.
    """
    if not isinstance(document, dict):
        raise TypeError(f"policy document must be a dict, got {type(document).__name__}")

    findings: list[Finding] = []

    for index, statement in enumerate(_statements(document)):
        if statement.get("Effect", "Allow") != "Allow":
            continue

        has_not_action = "NotAction" in statement
        has_not_resource = "NotResource" in statement
        actions = _as_list(statement.get("Action") or statement.get("NotAction"))
        resources = _as_list(statement.get("Resource") or statement.get("NotResource"))
        condition = statement.get("Condition", {})
        condition_str = str(condition)

        # ─── AIG001: NotAction/NotResource in agent policies ─────────────────
        if has_not_action or has_not_resource:
            findings.append(
                Finding(
                    "AIG001",
                    "high",
                    "Agent policy uses NotAction or NotResource — these grant everything "
                    "EXCEPT what's listed, which is almost always broader than intended "
                    "for an autonomous workload.",
                    "Replace negative policy matching with explicit allow lists. "
                    "An agent should only call the specific APIs it needs.",
                    index,
                )
            )

        # ─── AIG002: Wildcard actions ────────────────────────────────────────
        if any(a == "*" or a.endswith(":*") for a in actions):
            findings.append(
                Finding(
                    "AIG002",
                    "critical",
                    "Agent policy grants wildcard service or full-account actions. "
                    "An autonomous agent with '*' can do anything including deleting "
                    "the account's entire infrastructure.",
                    "Scope actions to the exact APIs the agent tool calls. "
                    "Use service-level wildcards only in dev environments with "
                    "a permission boundary as a safety net.",
                    index,
                )
            )

        # ─── AIG003: Wildcard resources ──────────────────────────────────────
        if any(r == "*" for r in resources):
            findings.append(
                Finding(
                    "AIG003",
                    "high",
                    "Agent policy grants access to all resources in the account. "
                    "Combined with tool-execution actions, this means the agent "
                    "can invoke any Lambda, read any secret, or run tasks anywhere.",
                    "Bind permissions to specific ARNs or use resource tags and "
                    "conditions (aws:ResourceTag) to limit blast radius.",
                    index,
                )
            )

        # ─── AIG004: PassRole without PassedToService ────────────────────────
        if any(
            _matches_any(a, {"iam:PassRole", "iam:passrole"}) for a in actions
        ) and "iam:PassedToService" not in condition_str:
            findings.append(
                Finding(
                    "AIG004",
                    "critical",
                    "iam:PassRole without iam:PassedToService condition. "
                    "An agent with unconstrained PassRole can escalate privileges "
                    "by passing a high-privilege role to any service it can invoke.",
                    "Add a Condition: {StringEquals: {iam:PassedToService: "
                    "'bedrock.amazonaws.com'}} (or whichever service runs the agent). "
                    "Also restrict the Resource to specific role ARNs.",
                    index,
                )
            )

        # ─── Per-action checks ───────────────────────────────────────────────
        seen_privilege = set()
        seen_tool_exec = set()
        seen_sensitive = set()
        seen_bedrock_cp = set()
        seen_sagemaker_cp = set()
        seen_egress = set()
        seen_anti_forensics = set()

        for action in actions:
            action_lower = action.lower()

            # AIG005: Privilege escalation actions
            if _matches_any(action, PRIVILEGE_ACTIONS) and action_lower not in seen_privilege:
                seen_privilege.add(action_lower)
                findings.append(
                    Finding(
                        "AIG005",
                        "critical",
                        f"Agent has privilege-management action '{action}'. "
                        "This lets the agent modify IAM policies, create roles, "
                        "or assume other identities — classic escalation path.",
                        "Separate agent runtime roles from IAM administration. "
                        "Agent runtime identities should NEVER have iam:* or "
                        "policy-modification permissions.",
                        index,
                    )
                )

            # AIG006: Tool execution without resource scoping
            if (
                _matches_any(action, TOOL_EXECUTION_PATTERNS)
                and any(r == "*" for r in resources)
                and action_lower not in seen_tool_exec
            ):
                seen_tool_exec.add(action_lower)
                findings.append(
                    Finding(
                        "AIG006",
                        "high",
                        f"Tool execution action '{action}' targets Resource: '*'. "
                        "The agent can invoke ANY function, endpoint, or task "
                        "in the account — not just its intended tools.",
                        "Restrict to specific ARNs: the Lambda functions, ECS tasks, "
                        "or Bedrock agents this tool is allowed to call. "
                        "Use resource tags for dynamic scoping.",
                        index,
                    )
                )

            # AIG007: Sensitive data access without principal tags
            if (
                _matches_any(action, SENSITIVE_DATA_PATTERNS)
                and "aws:PrincipalTag" not in condition_str
                and "aws:ResourceTag" not in condition_str
                and action_lower not in seen_sensitive
            ):
                seen_sensitive.add(action_lower)
                findings.append(
                    Finding(
                        "AIG007",
                        "medium",
                        f"Sensitive data action '{action}' has no principal-tag or "
                        "resource-tag condition. Without ABAC controls, any session "
                        "using this role can read all accessible secrets/data.",
                        "Add principal tags (aws:PrincipalTag/tenant, "
                        "aws:PrincipalTag/agent-id) or resource tags to ensure "
                        "the agent only accesses data belonging to its tenant.",
                        index,
                    )
                )

            # ─── NEW RULES: AIG008-AIG018 ─────────────────────────────────────

            # AIG008: Bedrock control plane — agent can modify itself
            if (
                _matches_any(action, BEDROCK_CONTROL_PLANE)
                and action_lower not in seen_bedrock_cp
            ):
                seen_bedrock_cp.add(action_lower)
                findings.append(
                    Finding(
                        "AIG008",
                        "critical",
                        f"Agent has Bedrock control-plane action '{action}'. "
                        "This lets the agent create or modify agents, knowledge bases, "
                        "or guardrails — it can reconfigure its own capabilities "
                        "or disable safety guardrails.",
                        "Agent runtime roles should only have bedrock:InvokeModel "
                        "and bedrock-agent-runtime:* (data plane). Move control-plane "
                        "actions to a separate deployment/admin role.",
                        index,
                    )
                )

            # AIG009: SageMaker control plane — agent can deploy models
            if (
                _matches_any(action, SAGEMAKER_CONTROL_PLANE)
                and action_lower not in seen_sagemaker_cp
            ):
                seen_sagemaker_cp.add(action_lower)
                findings.append(
                    Finding(
                        "AIG009",
                        "high",
                        f"Agent has SageMaker control-plane action '{action}'. "
                        "An agent that can deploy endpoints or start training jobs "
                        "could substitute a poisoned model or exfiltrate training data.",
                        "Agent runtime should only need sagemaker-runtime:InvokeEndpoint. "
                        "Move model management to a CI/CD pipeline role with "
                        "human approval gates.",
                        index,
                    )
                )

            # AIG010: Network egress — agent can create network paths
            if (
                _matches_any(action, NETWORK_EGRESS_PATTERNS)
                and action_lower not in seen_egress
            ):
                seen_egress.add(action_lower)
                findings.append(
                    Finding(
                        "AIG010",
                        "high",
                        f"Agent has network-modification action '{action}'. "
                        "This enables the agent to create network interfaces, "
                        "modify security groups, or deploy functions that establish "
                        "outbound connections to attacker infrastructure.",
                        "Agents should not manage network resources. Place them in "
                        "a VPC with restrictive egress rules managed by platform teams. "
                        "Use VPC endpoints for AWS service access.",
                        index,
                    )
                )

            # AIG011: Anti-forensics — agent can tamper with audit trails
            if (
                _matches_any(action, ANTI_FORENSICS_PATTERNS)
                and action_lower not in seen_anti_forensics
            ):
                seen_anti_forensics.add(action_lower)
                findings.append(
                    Finding(
                        "AIG011",
                        "critical",
                        f"Agent has audit-tampering action '{action}'. "
                        "A compromised agent could disable CloudTrail, delete logs, "
                        "or stop GuardDuty — hiding its malicious activity from "
                        "detection and incident response.",
                        "No agent runtime identity should ever have logging/monitoring "
                        "modification permissions. These belong to a break-glass admin "
                        "role with MFA + approval workflow.",
                        index,
                    )
                )

        # ─── AIG012: Excessive action breadth ────────────────────────────────
        # If a single statement grants more than 15 distinct actions to an agent,
        # it's probably an overly broad copypasta from a human IAM role.
        action_count = _count_actions(actions)
        if action_count > 15:
            findings.append(
                Finding(
                    "AIG012",
                    "medium",
                    f"Statement grants {action_count} distinct actions. "
                    "Agent policies should follow single-responsibility — each "
                    "statement should map to one tool capability. Broad statements "
                    "suggest a human-role policy was copied for an agent.",
                    "Split into multiple statements, one per tool/capability. "
                    "This makes it auditable: each statement = one tool the agent can use.",
                    index,
                )
            )

        # ─── AIG013: No condition keys at all ────────────────────────────────
        # Agent policies without ANY conditions lack tenant isolation and
        # session binding.
        if not condition and any(r == "*" for r in resources):
            findings.append(
                Finding(
                    "AIG013",
                    "medium",
                    "Statement has Resource: '*' and zero Condition keys. "
                    "Agent policies should use conditions for tenant isolation "
                    "(aws:PrincipalTag), request scoping (aws:RequestedRegion), "
                    "or session binding (aws:TokenIssueTime).",
                    "Add at minimum: aws:RequestedRegion to limit geographic blast radius, "
                    "and aws:PrincipalTag/tenant for multi-tenant isolation.",
                    index,
                )
            )

        # ─── AIG014: S3 write without prefix scoping ─────────────────────────
        s3_write_actions = {"s3:putobject", "s3:deleteobject", "s3:putobjectacl"}
        if any(a.lower() in s3_write_actions for a in actions):
            # Check if resources are scoped to a meaningful prefix.
            # arn:aws:s3:::bucket/* is too broad (full bucket).
            # arn:aws:s3:::bucket/prefix/* is fine (scoped to prefix).
            # Resource: "*" is too broad.
            has_broad_s3 = False
            for r in resources:
                if r == "*":
                    has_broad_s3 = True
                    break
                if r.startswith("arn:aws:s3:::"):
                    # Extract the path portion after the bucket name
                    path_part = r[len("arn:aws:s3:::"):]
                    # bucket/* or bucket* = entire bucket, no prefix
                    if "/" not in path_part:
                        has_broad_s3 = True
                        break
                    bucket_and_path = path_part.split("/", 1)
                    key_prefix = bucket_and_path[1] if len(bucket_and_path) > 1 else ""
                    # Just "*" or empty after the slash = entire bucket
                    if key_prefix in ("*", ""):
                        has_broad_s3 = True
                        break

            if has_broad_s3:
                findings.append(
                    Finding(
                        "AIG014",
                        "high",
                        "S3 write/delete actions without key-prefix scoping. "
                        "The agent can overwrite or delete any object in the bucket. "
                        "A prompt injection could instruct the agent to corrupt "
                        "training data or exfiltrate to an attacker-controlled prefix.",
                        "Scope S3 resources to a specific prefix: "
                        "arn:aws:s3:::bucket-name/agent-workspace/${aws:PrincipalTag/agent-id}/*",
                        index,
                    )
                )

        # ─── AIG015: Bedrock InvokeModel without model ID scoping ────────────
        bedrock_invoke = {"bedrock:invokemodel", "bedrock:invokemodelwithresponsestream"}
        if any(a.lower() in bedrock_invoke for a in actions):
            # Check if resource is scoped to specific model IDs
            has_model_scope = any(
                ":foundation-model/" in r or ":provisioned-model/" in r
                or ":custom-model/" in r
                for r in resources
            )
            if not has_model_scope:
                findings.append(
                    Finding(
                        "AIG015",
                        "medium",
                        "Bedrock InvokeModel without model-ID resource scoping. "
                        "The agent can call any foundation model in the account, "
                        "including expensive ones (Claude Opus, large Titan models) "
                        "leading to unexpected costs or capability escalation.",
                        "Scope Resource to specific model ARNs: "
                        "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-haiku* "
                        "to limit which models the agent can invoke.",
                        index,
                    )
                )

        # ─── AIG016: Lambda invoke without function name scoping ─────────────
        lambda_invoke = {"lambda:invokefunction", "lambda:invokeasync"}
        if any(a.lower() in lambda_invoke for a in actions):
            has_function_scope = any(
                ":function:" in r and not r.endswith(":function:*")
                for r in resources
                if r.startswith("arn:")
            )
            if not has_function_scope and any(r == "*" for r in resources):
                findings.append(
                    Finding(
                        "AIG016",
                        "high",
                        "Lambda invoke without function-name resource scoping. "
                        "The agent can invoke ANY Lambda in the account — including "
                        "admin utilities, data pipelines, or credential-rotation functions.",
                        "Scope to the specific tool functions: "
                        "arn:aws:lambda:REGION:ACCOUNT:function:agent-tool-* "
                        "using a naming convention and wildcard suffix.",
                        index,
                    )
                )

        # ─── AIG017: STS AssumeRole without session tags ─────────────────────
        if any(
            _matches_any(a, {"sts:AssumeRole"}) for a in actions
        ) and "aws:RequestTag" not in condition_str and "sts:TransitiveTagKeys" not in condition_str:
            findings.append(
                Finding(
                    "AIG017",
                    "high",
                    "sts:AssumeRole without session tag requirements. "
                    "The agent can assume roles without passing identifying tags, "
                    "making it impossible to trace which agent session performed "
                    "downstream actions.",
                    "Require aws:RequestTag/agent-session-id and "
                    "sts:TransitiveTagKeys to propagate agent identity "
                    "across role chains.",
                    index,
                )
            )

        # ─── AIG018: DynamoDB/RDS full-table access ──────────────────────────
        db_scan_actions = {"dynamodb:scan", "dynamodb:query", "rds-data:executestatement"}
        if any(a.lower() in db_scan_actions for a in actions):
            has_condition_limit = (
                "dynamodb:LeadingKeys" in condition_str
                or "dynamodb:Attributes" in condition_str
                or "aws:PrincipalTag" in condition_str
            )
            if not has_condition_limit and any(r == "*" for r in resources):
                findings.append(
                    Finding(
                        "AIG018",
                        "high",
                        "Database read actions without row-level or attribute-level scoping. "
                        "The agent can scan entire tables, potentially exfiltrating "
                        "PII, credentials, or business-critical data beyond its scope.",
                        "Use DynamoDB fine-grained access (dynamodb:LeadingKeys condition) "
                        "or restrict to specific table ARNs with attribute filtering. "
                        "For RDS Data API, use parameterized queries via application code.",
                        index,
                    )
                )

    return findings


# ─── Trust policy rules ───────────────────────────────────────────────────────


def scan_trust_policy(document: dict[str, Any]) -> list[Finding]:
    """Scan an IAM role trust policy (AssumeRolePolicyDocument) for agent identity risks.

    Rules
    -----
    AIG-TP001  CRITICAL  Wildcard principal — any AWS identity can assume this role.
    AIG-TP002  HIGH      Cross-account trust without sts:ExternalId (confused-deputy).
    AIG-TP003  HIGH      Cross-account trust without aws:SourceArn (lateral-movement).
    """
    if not isinstance(document, dict):
        raise TypeError(f"trust policy document must be a dict, got {type(document).__name__}")

    findings: list[Finding] = []

    for index, statement in enumerate(_statements(document)):
        if statement.get("Effect", "Allow") != "Allow":
            continue

        principal = statement.get("Principal")
        condition = statement.get("Condition") or {}

        # Flatten principals into a simple list for analysis
        principals_flat: list[str] = []
        if isinstance(principal, str):
            principals_flat = [principal]
        elif isinstance(principal, dict):
            for v in principal.values():
                principals_flat.extend(_as_list(v))
        elif isinstance(principal, list):
            principals_flat = [str(p) for p in principal]

        # AIG-TP001: Wildcard principal
        if principal == "*" or "*" in principals_flat:
            findings.append(
                Finding(
                    "AIG-TP001",
                    "critical",
                    "Trust policy grants AssumeRole to wildcard principal '*'. "
                    "Any AWS identity — or unauthenticated caller via "
                    "cognito-identity — can assume this agent role.",
                    "Replace '*' with the specific service principal "
                    "(e.g., bedrock.amazonaws.com) or account ARN that "
                    "legitimately invokes this agent.",
                    index,
                )
            )

        # Identify cross-account principals for TP002/TP003
        cross_account_arns = [
            p for p in principals_flat if p.startswith("arn:aws:iam::")
        ]
        if cross_account_arns:
            condition_str = str(condition)

            # AIG-TP002: Missing ExternalId
            if "sts:ExternalId" not in condition_str:
                findings.append(
                    Finding(
                        "AIG-TP002",
                        "high",
                        f"Cross-account trust to {cross_account_arns} without "
                        "sts:ExternalId condition. Any resource in the trusted "
                        "account can assume this role (confused-deputy).",
                        "Add Condition: {StringEquals: {sts:ExternalId: '<shared-secret>'}}. "
                        "Generate a cryptographically random ExternalId per trust relationship.",
                        index,
                    )
                )

            # AIG-TP003: Missing SourceArn
            if "aws:SourceArn" not in condition_str and "aws:sourceArn" not in condition_str:
                findings.append(
                    Finding(
                        "AIG-TP003",
                        "high",
                        f"Cross-account trust to {cross_account_arns} without "
                        "aws:SourceArn condition. Without source-ARN pinning, "
                        "any resource in the trusted account can trigger "
                        "role assumption for lateral movement.",
                        "Add ArnLike condition on aws:SourceArn scoped to the "
                        "specific resource (Lambda function, ECS task, etc.) "
                        "that should assume this role.",
                        index,
                    )
                )

    return findings
