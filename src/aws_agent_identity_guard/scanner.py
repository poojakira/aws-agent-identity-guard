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
