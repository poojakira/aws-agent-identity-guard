"""
aws_agent_identity_guard/remediate.py
────────────────────────────────────────────────────────────────────────────────
Deterministic IaC remediation generator.

Takes scanner findings and produces ready-to-apply IaC fixes from
rule-keyed templates (no ML/LLM involved — output is fully deterministic):
- Terraform HCL for IAM policy/role corrections
- CloudFormation YAML snippets
- Raw IAM policy JSON (fixed version)

This bridges the gap between "we found a problem" and "here's the fix" —
turning a security scanner into an infrastructure automation aid.

No external AI service required. Uses rule-based templates with context
injection. Zero cost, zero network calls, zero API keys.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .scanner import Finding


@dataclass
class Remediation:
    """A generated fix for one or more findings on a single resource."""

    resource_name: str
    resource_arn: str | None
    findings_addressed: list[str]
    terraform_hcl: str
    cloudformation_yaml: str
    fixed_policy_json: dict[str, Any]
    explanation: str


# ─── Template-based remediation generators ────────────────────────────────────

_PASSROLE_FIX = """resource "aws_iam_role_policy" "{role_name}_passrole_scoped" {{
  name = "passrole-scoped-to-service"
  role = aws_iam_role.{role_name}.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "PassRoleToSpecificService"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "arn:aws:iam::*:role/{role_name}-execution"
        Condition = {{
          StringEquals = {{
            "iam:PassedToService" = "{target_service}"
          }}
        }}
      }}
    ]
  }})
}}"""

_BEDROCK_SCOPED_FIX = """resource "aws_iam_role_policy" "{role_name}_bedrock_invoke" {{
  name = "bedrock-invoke-scoped"
  role = aws_iam_role.{role_name}.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "InvokeSpecificModel"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = "arn:aws:bedrock:*::foundation-model/{model_id}"
      }}
    ]
  }})
}}"""

_LAMBDA_SCOPED_FIX = """resource "aws_iam_role_policy" "{role_name}_lambda_tools" {{
  name = "lambda-invoke-scoped-to-tools"
  role = aws_iam_role.{role_name}.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "InvokeApprovedToolFunctions"
        Effect = "Allow"
        Action = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:*:*:function:agent-tool-*"
        Condition = {{
          StringEquals = {{
            "aws:PrincipalTag/agent-owner" = "{owner_tag}"
          }}
        }}
      }}
    ]
  }})
}}"""

_DENY_BOUNDARY = """resource "aws_iam_policy" "agent_permission_boundary" {{
  name        = "AgentPermissionBoundary"
  description = "Caps maximum permissions for AI agent roles"

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "AllowCoreAgentActions"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "lambda:InvokeFunction",
          "s3:GetObject",
          "s3:PutObject",
          "logs:PutLogEvents",
          "logs:CreateLogStream"
        ]
        Resource = "*"
      }},
      {{
        Sid      = "DenyDangerousActions"
        Effect   = "Deny"
        Action   = [
          "iam:*",
          "sts:AssumeRole",
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "guardduty:DeleteDetector",
          "config:StopConfigurationRecorder",
          "bedrock:CreateAgent",
          "bedrock:UpdateAgent",
          "bedrock:DeleteGuardrail",
          "sagemaker:CreateEndpoint",
          "ec2:CreateNetworkInterface",
          "ec2:AuthorizeSecurityGroupEgress"
        ]
        Resource = "*"
      }}
    ]
  }})
}}

resource "aws_iam_role" "{role_name}" {{
  # ... existing role config ...
  permissions_boundary = aws_iam_policy.agent_permission_boundary.arn
}}"""

_SESSION_TAGS_FIX = """resource "aws_iam_role_policy" "{role_name}_assume_with_tags" {{
  name = "assume-role-require-session-tags"
  role = aws_iam_role.{role_name}.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "AssumeWithSessionTags"
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Resource = "{target_role_arn}"
        Condition = {{
          StringLike = {{
            "aws:RequestTag/agent-session-id" = "*"
          }}
          "ForAllValues:StringEquals" = {{
            "sts:TransitiveTagKeys" = ["agent-session-id", "tenant"]
          }}
        }}
      }}
    ]
  }})
}}"""


def generate_remediations(
    findings: list[Finding],
    resource_name: str = "agent-role",
    resource_arn: str | None = None,
    context: dict[str, str] | None = None,
) -> list[Remediation]:
    """Generate IaC remediation code from scanner findings.

    This is the core deterministic remediation generator. It takes findings
    and produces ready-to-apply Terraform HCL, CloudFormation YAML, and fixed
    policy JSON from rule-keyed templates (no ML/LLM involved).

    Parameters
    ----------
    findings : list[Finding]
        Findings from scan_policy_document() or scan_trust_policy().
    resource_name : str
        IAM role or user name to generate fixes for.
    resource_arn : str, optional
        Full ARN of the resource.
    context : dict, optional
        Additional context for template rendering:
        - "target_service": e.g., "bedrock.amazonaws.com"
        - "model_id": e.g., "anthropic.claude-3-haiku-20240307-v1:0"
        - "owner_tag": e.g., "security-team"
        - "target_role_arn": for AssumeRole fixes

    Returns
    -------
    list[Remediation]
        One Remediation per addressable finding group.
    """
    ctx = context or {}
    target_service = ctx.get("target_service", "bedrock.amazonaws.com")
    model_id = ctx.get("model_id", "anthropic.claude-3-haiku-20240307-v1:0")
    owner_tag = ctx.get("owner_tag", "security-team")
    target_role_arn = ctx.get("target_role_arn", "arn:aws:iam::*:role/downstream-*")

    # Normalize role name for Terraform resource naming
    tf_name = resource_name.replace("-", "_").replace(".", "_").lower()

    remediations: list[Remediation] = []
    addressed: set[str] = set()

    for finding in findings:
        if finding.rule_id in addressed:
            continue

        if finding.rule_id == "AIG004":
            # PassRole without constraint
            hcl = _PASSROLE_FIX.format(role_name=tf_name, target_service=target_service)
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PassRoleScopedToService",
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": f"arn:aws:iam::*:role/{resource_name}-execution",
                        "Condition": {"StringEquals": {"iam:PassedToService": target_service}},
                    }
                ],
            }
            remediations.append(
                Remediation(
                    resource_name=resource_name,
                    resource_arn=resource_arn,
                    findings_addressed=["AIG004"],
                    terraform_hcl=hcl,
                    cloudformation_yaml=_to_cfn_yaml("PassRoleScoped", policy),
                    fixed_policy_json=policy,
                    explanation=(
                        f"Scoped iam:PassRole to only pass roles to {target_service}. "
                        "The agent can no longer pass arbitrary roles to arbitrary services."
                    ),
                )
            )
            addressed.add("AIG004")

        elif finding.rule_id == "AIG015":
            # Bedrock InvokeModel without model scoping
            hcl = _BEDROCK_SCOPED_FIX.format(role_name=tf_name, model_id=model_id)
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "InvokeSpecificModel",
                        "Effect": "Allow",
                        "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                        "Resource": f"arn:aws:bedrock:*::foundation-model/{model_id}",
                    }
                ],
            }
            remediations.append(
                Remediation(
                    resource_name=resource_name,
                    resource_arn=resource_arn,
                    findings_addressed=["AIG015"],
                    terraform_hcl=hcl,
                    cloudformation_yaml=_to_cfn_yaml("BedrockInvokeScoped", policy),
                    fixed_policy_json=policy,
                    explanation=(
                        f"Restricted Bedrock invocation to model {model_id}. "
                        "Prevents cost overruns from calling expensive models and "
                        "capability escalation from accessing more powerful models."
                    ),
                )
            )
            addressed.add("AIG015")

        elif finding.rule_id in ("AIG006", "AIG016"):
            # Lambda/tool invoke without scoping
            hcl = _LAMBDA_SCOPED_FIX.format(role_name=tf_name, owner_tag=owner_tag)
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "InvokeApprovedToolFunctions",
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": "arn:aws:lambda:*:*:function:agent-tool-*",
                        "Condition": {"StringEquals": {"aws:PrincipalTag/agent-owner": owner_tag}},
                    }
                ],
            }
            remediations.append(
                Remediation(
                    resource_name=resource_name,
                    resource_arn=resource_arn,
                    findings_addressed=["AIG006", "AIG016"],
                    terraform_hcl=hcl,
                    cloudformation_yaml=_to_cfn_yaml("LambdaToolsScoped", policy),
                    fixed_policy_json=policy,
                    explanation=(
                        "Restricted Lambda invocation to functions matching agent-tool-* "
                        f"naming convention, owned by {owner_tag}. Uses ABAC tags for "
                        "multi-tenant isolation."
                    ),
                )
            )
            addressed.add("AIG006")
            addressed.add("AIG016")

        elif finding.rule_id == "AIG017":
            # AssumeRole without session tags
            hcl = _SESSION_TAGS_FIX.format(role_name=tf_name, target_role_arn=target_role_arn)
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AssumeWithSessionTags",
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": target_role_arn,
                        "Condition": {
                            "StringLike": {"aws:RequestTag/agent-session-id": "*"},
                            "ForAllValues:StringEquals": {
                                "sts:TransitiveTagKeys": ["agent-session-id", "tenant"]
                            },
                        },
                    }
                ],
            }
            remediations.append(
                Remediation(
                    resource_name=resource_name,
                    resource_arn=resource_arn,
                    findings_addressed=["AIG017"],
                    terraform_hcl=hcl,
                    cloudformation_yaml=_to_cfn_yaml("AssumeRoleWithTags", policy),
                    fixed_policy_json=policy,
                    explanation=(
                        "Required session tags (agent-session-id, tenant) for role assumption. "
                        "Enables tracing which agent session performed downstream actions."
                    ),
                )
            )
            addressed.add("AIG017")

        elif finding.rule_id in ("AIG005", "AIG008", "AIG009", "AIG010", "AIG011"):
            # Dangerous actions — suggest permission boundary
            hcl = _DENY_BOUNDARY.format(role_name=tf_name)
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowCoreAgentActions",
                        "Effect": "Allow",
                        "Action": [
                            "bedrock:InvokeModel",
                            "lambda:InvokeFunction",
                            "s3:GetObject",
                            "s3:PutObject",
                            "logs:PutLogEvents",
                            "logs:CreateLogStream",
                        ],
                        "Resource": "*",
                    },
                    {
                        "Sid": "DenyDangerousActions",
                        "Effect": "Deny",
                        "Action": [
                            "iam:*",
                            "sts:AssumeRole",
                            "cloudtrail:StopLogging",
                            "guardduty:DeleteDetector",
                            "bedrock:CreateAgent",
                            "sagemaker:CreateEndpoint",
                            "ec2:CreateNetworkInterface",
                        ],
                        "Resource": "*",
                    },
                ],
            }
            addressed_rules = [
                r
                for r in ("AIG005", "AIG008", "AIG009", "AIG010", "AIG011")
                if any(f.rule_id == r for f in findings)
            ]
            remediations.append(
                Remediation(
                    resource_name=resource_name,
                    resource_arn=resource_arn,
                    findings_addressed=addressed_rules,
                    terraform_hcl=hcl,
                    cloudformation_yaml=_to_cfn_yaml("AgentBoundary", policy),
                    fixed_policy_json=policy,
                    explanation=(
                        "Attached a permission boundary that denies all dangerous actions "
                        "(IAM modification, audit tampering, control-plane, network). "
                        "The boundary caps effective permissions regardless of what identity "
                        "policies grant. This is defense-in-depth — even if a policy is "
                        "misconfigured, the boundary prevents escalation."
                    ),
                )
            )
            for r in addressed_rules:
                addressed.add(r)

    return remediations


def _to_cfn_yaml(logical_id: str, policy: dict[str, Any]) -> str:
    """Convert a policy dict to CloudFormation YAML snippet."""
    # Simple YAML generation without external deps
    statements = policy.get("Statement", [])
    lines = [
        f"  {logical_id}Policy:",
        "    Type: AWS::IAM::ManagedPolicy",
        "    Properties:",
        "      PolicyDocument:",
        "        Version: '2012-10-17'",
        "        Statement:",
    ]
    for stmt in statements:
        lines.append(f"          - Sid: {stmt.get('Sid', '')}")
        lines.append(f"            Effect: {stmt['Effect']}")
        action = stmt["Action"]
        if isinstance(action, list):
            lines.append("            Action:")
            for a in action:
                lines.append(f"              - '{a}'")
        else:
            lines.append(f"            Action: '{action}'")
        resource = stmt["Resource"]
        if isinstance(resource, list):
            lines.append("            Resource:")
            for r in resource:
                lines.append(f"              - '{r}'")
        else:
            lines.append(f"            Resource: '{resource}'")
        if "Condition" in stmt:
            lines.append("            Condition:")
            lines.append("              # See fixed_policy_json for full condition block")
    return "\n".join(lines)


def remediate_to_json(remediations: list[Remediation]) -> str:
    """Serialize remediations to JSON for API output or file storage."""
    return json.dumps(
        [
            {
                "resource": r.resource_name,
                "resource_arn": r.resource_arn,
                "findings_fixed": r.findings_addressed,
                "explanation": r.explanation,
                "terraform": r.terraform_hcl,
                "cloudformation": r.cloudformation_yaml,
                "policy_json": r.fixed_policy_json,
            }
            for r in remediations
        ],
        indent=2,
    )
