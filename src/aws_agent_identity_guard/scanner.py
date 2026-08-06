from __future__ import annotations

from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from typing import Any

PRIVILEGE_ACTIONS = {
    "iam:*",
    "iam:CreateRole",
    "iam:PutRolePolicy",
    "iam:AttachRolePolicy",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "sts:AssumeRole",
}

TOOL_EXECUTION_PATTERNS = (
    "lambda:InvokeFunction",
    "ssm:SendCommand",
    "ssm:StartSession",
    "states:StartExecution",
    "ecs:RunTask",
    "bedrock:Invoke*",
    "bedrock-agent*:Invoke*",
)

SENSITIVE_DATA_PATTERNS = (
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter*",
    "kms:Decrypt",
    "s3:GetObject",
    "logs:GetLogEvents",
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    remediation: str
    statement_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _matches_any(action: str, patterns: set[str] | tuple[str, ...]) -> bool:
    return any(fnmatchcase(action.lower(), pattern.lower()) for pattern in patterns)


def _statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    statement = document.get("Statement", [])
    if isinstance(statement, dict):
        return [statement]
    if isinstance(statement, list):
        return [s for s in statement if isinstance(s, dict)]
    return []


def scan_policy_document(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for index, statement in enumerate(_statements(document)):
        if statement.get("Effect", "Allow") != "Allow":
            continue
        actions = _as_list(statement.get("Action") or statement.get("NotAction"))
        resources = _as_list(statement.get("Resource") or statement.get("NotResource"))
        condition = statement.get("Condition", {})

        if "NotAction" in statement or "NotResource" in statement:
            findings.append(
                Finding(
                    "AIG001",
                    "high",
                    "Agent policy uses NotAction or NotResource, which is difficult to reason about for autonomous workloads.",
                    "Replace negative policy matching with explicit allow lists for each tool action and resource.",
                    index,
                )
            )

        if any(a == "*" or a.endswith(":*") for a in actions):
            findings.append(
                Finding(
                    "AIG002",
                    "critical",
                    "Agent policy grants wildcard service or account actions.",
                    "Scope actions to the exact services and APIs the agent tool is allowed to call.",
                    index,
                )
            )

        if any(r == "*" for r in resources):
            findings.append(
                Finding(
                    "AIG003",
                    "high",
                    "Agent policy grants access to all resources.",
                    "Bind permissions to specific ARNs and add tenant/session conditions where possible.",
                    index,
                )
            )

        if any(
            _matches_any(a, {"iam:PassRole"}) for a in actions
        ) and "iam:PassedToService" not in str(condition):
            findings.append(
                Finding(
                    "AIG004",
                    "critical",
                    "iam:PassRole is allowed without an iam:PassedToService condition.",
                    "Constrain PassRole to the one AWS service that runs the agent or tool workload.",
                    index,
                )
            )

        for action in actions:
            if _matches_any(action, PRIVILEGE_ACTIONS):
                findings.append(
                    Finding(
                        "AIG005",
                        "critical",
                        f"Agent policy includes privilege-management action {action}.",
                        "Separate agent runtime roles from IAM administration and role-broker permissions.",
                        index,
                    )
                )
            if _matches_any(action, TOOL_EXECUTION_PATTERNS) and any(r == "*" for r in resources):
                findings.append(
                    Finding(
                        "AIG006",
                        "high",
                        f"Tool execution action {action} is not resource-scoped.",
                        "Restrict tool execution to approved Lambda, SSM, Step Functions, ECS, or Bedrock resources.",
                        index,
                    )
                )
            if _matches_any(action, SENSITIVE_DATA_PATTERNS) and "aws:PrincipalTag" not in str(
                condition
            ):
                findings.append(
                    Finding(
                        "AIG007",
                        "medium",
                        f"Sensitive-data action {action} has no visible principal/session tag condition.",
                        "Use principal tags, session tags, or resource tags to bind data access to agent owner and tenant context.",
                        index,
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Trust-policy rules
# ---------------------------------------------------------------------------

def _is_cross_account_principal(principal: Any) -> bool:
    """Return True if any principal ARN references an account via arn:aws:iam::."""
    arns = _as_list(principal)
    return any(
        arn.startswith("arn:aws:iam::") and not arn.endswith(":root")
        or (arn.startswith("arn:aws:iam::") and arn.endswith(":root"))
        for arn in arns
    )


def scan_trust_policy(document: dict[str, Any]) -> list[Finding]:
    """Scan an IAM role *trust* policy (AssumeRolePolicyDocument) for agent identity risks.

    Rules
    -----
    AIG-TP001  CRITICAL  Wildcard principal — any AWS identity can assume this role.
    AIG-TP002  HIGH      Cross-account trust without sts:ExternalId condition (confused-deputy).
    AIG-TP003  HIGH      Cross-account trust without aws:SourceArn condition (lateral-movement).
    """
    if not isinstance(document, dict):
        raise TypeError(f"trust policy document must be a dict, got {type(document).__name__}")

    findings: list[Finding] = []

    for index, statement in enumerate(_statements(document)):
        if statement.get("Effect", "Allow") != "Allow":
            continue

        principal = statement.get("Principal")
        condition = statement.get("Condition") or {}

        # AIG-TP001 — wildcard principal
        principals_flat: list[str] = []
        if isinstance(principal, str):
            principals_flat = [principal]
        elif isinstance(principal, dict):
            for v in principal.values():
                principals_flat.extend(_as_list(v))
        elif isinstance(principal, list):
            principals_flat = [str(p) for p in principal]

        if principal == "*" or "*" in principals_flat:
            findings.append(
                Finding(
                    "AIG-TP001",
                    "critical",
                    "Trust policy grants AssumeRole to a wildcard principal ('*'). "
                    "Any AWS identity — or unauthenticated caller — can assume this role.",
                    "Replace '*' with the specific AWS account, service, or role ARN that "
                    "legitimately needs to assume this role.",
                    index,
                )
            )

        # AIG-TP002 / AIG-TP003 — cross-account trust conditions
        # Identify cross-account ARN principals (arn:aws:iam::<account>:...)
        cross_account_arns = [
            p for p in principals_flat if p.startswith("arn:aws:iam::")
        ]
        if cross_account_arns:
            condition_str = str(condition)

            # AIG-TP002 — missing ExternalId
            if "sts:ExternalId" not in condition_str:
                findings.append(
                    Finding(
                        "AIG-TP002",
                        "high",
                        f"Cross-account trust to {cross_account_arns} is missing a "
                        "sts:ExternalId condition. This enables confused-deputy attacks "
                        "from any resource in the trusted account.",
                        "Add a StringEquals condition on sts:ExternalId with a non-guessable "
                        "value agreed with the trusted account.",
                        index,
                    )
                )

            # AIG-TP003 — missing aws:SourceArn
            if "aws:SourceArn" not in condition_str and "aws:sourceArn" not in condition_str:
                findings.append(
                    Finding(
                        "AIG-TP003",
                        "high",
                        f"Cross-account trust to {cross_account_arns} is missing an "
                        "aws:SourceArn condition. Without it, any resource in the trusted "
                        "account can trigger role assumption.",
                        "Add a StringEquals or ArnLike condition on aws:SourceArn scoped "
                        "to the specific resource ARN that should be allowed to assume this role.",
                        index,
                    )
                )

    return findings
