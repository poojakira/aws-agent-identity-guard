"""
aws_agent_identity_guard/escalation_engine.py
────────────────────────────────────────────────────────────────────────────────
Privilege escalation detection engine for AI agent identities.

Detects known privilege-escalation techniques available to an agent based on
its effective permissions. Implements a comprehensive catalog of 22+ AWS
escalation patterns mapped to MITRE ATT&CK techniques.

Each detected pattern produces an EscalationPath containing:
  • technique: Name of the escalation technique
  • required_permissions: IAM actions needed to execute
  • impact: Description of what is gained
  • severity: CRITICAL/HIGH/MEDIUM/LOW
  • mitre_id: MITRE ATT&CK technique identifier
  • remediation: Recommended fix

Detection catalog covers:
  • IAM policy manipulation (CreatePolicyVersion, SetDefaultPolicyVersion, etc.)
  • PassRole to compute services (Lambda, ECS, EC2, SageMaker, CloudFormation)
  • Role/user creation and policy attachment
  • Trust policy modification
  • Cross-account assumption
  • Credential generation (access keys, login profiles)
  • Service-specific escalation (Glue, Data Pipeline, Bedrock, SSM)
  • Secrets/credential chain attacks
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aws_agent_identity_guard.models import (
    AgentIdentity,
    EffectiveEffect,
    EffectivePermission,
)

logger = logging.getLogger(__name__)


# ─── Severity Classification ─────────────────────────────────────────────────


class EscalationSeverity(str, Enum):
    """Severity level of a detected escalation path."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ─── Escalation Path Data Model ──────────────────────────────────────────────


@dataclass
class EscalationPath:
    """
    A detected privilege escalation technique available to an agent.

    Represents a specific, known escalation pattern that the agent's current
    permissions enable. Each path includes full context for security teams
    to assess and remediate.

    Attributes:
        technique: Human-readable name of the escalation technique.
        required_permissions: List of IAM actions required to execute this technique.
        impact: Description of the privilege gained if exploited.
        severity: Risk severity classification.
        mitre_id: MITRE ATT&CK technique identifier (e.g., T1078.004).
        remediation: Recommended remediation steps.
        matched_permissions: The specific permissions from the agent that triggered detection.
        description: Extended description of the attack scenario.
    """

    technique: str
    required_permissions: list[str]
    impact: str
    severity: EscalationSeverity
    mitre_id: str
    remediation: str
    matched_permissions: list[str] = field(default_factory=list)
    description: str = ""

    def __post_init__(self) -> None:
        """Validate escalation path fields."""
        if not self.technique:
            raise ValueError("technique cannot be empty")
        if not self.required_permissions:
            raise ValueError("required_permissions cannot be empty")
        if isinstance(self.severity, str):
            self.severity = EscalationSeverity(self.severity)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "technique": self.technique,
            "required_permissions": list(self.required_permissions),
            "impact": self.impact,
            "severity": self.severity.value,
            "mitre_id": self.mitre_id,
            "remediation": self.remediation,
            "matched_permissions": list(self.matched_permissions),
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EscalationPath:
        """Deserialize from a dictionary."""
        return cls(
            technique=data["technique"],
            required_permissions=data["required_permissions"],
            impact=data["impact"],
            severity=EscalationSeverity(data["severity"]),
            mitre_id=data["mitre_id"],
            remediation=data["remediation"],
            matched_permissions=data.get("matched_permissions", []),
            description=data.get("description", ""),
        )


# ─── Escalation Pattern Definition ───────────────────────────────────────────


@dataclass(frozen=True)
class _EscalationPattern:
    """
    Internal definition of a known escalation pattern.

    Used by the detection engine to match against agent permissions.

    Attributes:
        technique: Name of the technique.
        required_actions: Set of IAM actions that must ALL be present (AND logic).
        any_of_actions: Set of IAM actions where at least one must be present (OR logic).
        impact: Impact description.
        severity: Severity level.
        mitre_id: MITRE ATT&CK ID.
        remediation: Remediation guidance.
        description: Extended description.
    """

    technique: str
    required_actions: frozenset[str]  # ALL must be present
    any_of_actions: frozenset[str] = frozenset()  # At least one must be present (if non-empty)
    impact: str = ""
    severity: EscalationSeverity = EscalationSeverity.HIGH
    mitre_id: str = ""
    remediation: str = ""
    description: str = ""


# ─── Escalation Pattern Catalog ───────────────────────────────────────────────

_ESCALATION_PATTERNS: list[_EscalationPattern] = [
    # 1. CreatePolicyVersion - create a new admin policy version
    _EscalationPattern(
        technique="CreatePolicyVersion",
        required_actions=frozenset({"iam:CreatePolicyVersion"}),
        impact=(
            "Create a new version of an existing managed policy with admin permissions, "
            "then set it as default to gain full administrative access."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitre_id="T1098.003",
        remediation=(
            "Remove iam:CreatePolicyVersion permission. Use AWS Organizations SCPs to "
            "deny policy modification. Enable CloudTrail monitoring for IAM policy changes."
        ),
        description=(
            "An agent with iam:CreatePolicyVersion can create a new version of any "
            "customer-managed policy with Action:* Resource:*, effectively granting "
            "itself administrative access."
        ),
    ),
    # 2. SetDefaultPolicyVersion - activate old permissive version
    _EscalationPattern(
        technique="SetDefaultPolicyVersion",
        required_actions=frozenset({"iam:SetDefaultPolicyVersion"}),
        impact=(
            "Activate a previously-created permissive policy version, restoring "
            "administrative access that was supposedly revoked."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitre_id="T1098.003",
        remediation=(
            "Remove iam:SetDefaultPolicyVersion permission. Delete old policy versions "
            "after deprecation. Monitor for policy version changes via CloudTrail."
        ),
        description=(
            "If a policy has older versions with broader permissions, this action allows "
            "reactivating them without creating new policy content."
        ),
    ),
    # 3. PassRole + Lambda (execute as privileged role)
    _EscalationPattern(
        technique="PassRole to Lambda",
        required_actions=frozenset({"iam:PassRole"}),
        any_of_actions=frozenset({"lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"}),
        impact=(
            "Pass a high-privilege role to a Lambda function, then execute arbitrary code "
            "with that role's permissions."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitre_id="T1548.002",
        remediation=(
            "Restrict iam:PassRole with conditions (iam:PassedToService=lambda.amazonaws.com). "
            "Limit passable roles to least-privilege roles only. Use permission boundaries."
        ),
        description=(
            "Agent passes an administrative role to a Lambda function it controls, "
            "then invokes the function to execute commands with that role's credentials."
        ),
    ),
    # 4. PassRole + CloudFormation
    _EscalationPattern(
        technique="PassRole to CloudFormation",
        required_actions=frozenset({"iam:PassRole", "cloudformation:CreateStack"}),
        impact=(
            "Pass an admin role to CloudFormation and deploy a stack that creates "
            "arbitrary resources (IAM roles, access keys, etc.) with full privilege."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitre_id="T1548.002",
        remediation=(
            "Restrict iam:PassRole to specific CloudFormation service roles. "
            "Use CloudFormation StackSets with guardrails. Require stack review processes."
        ),
        description=(
            "CloudFormation stacks execute with the passed role's permissions, allowing "
            "creation of any AWS resource the role is authorized for."
        ),
    ),
    # 5. AttachRolePolicy (attach AdministratorAccess)
    _EscalationPattern(
        technique="AttachRolePolicy",
        required_actions=frozenset({"iam:AttachRolePolicy"}),
        impact=(
            "Attach the AdministratorAccess managed policy (or any other policy) "
            "to the agent's own role or any other role."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitre_id="T1098.003",
        remediation=(
            "Remove iam:AttachRolePolicy. Use permission boundaries to limit maximum "
            "attainable privilege. Restrict via resource conditions to specific roles."
        ),
        description=(
            "Direct privilege escalation by attaching a high-privilege managed policy "
            "to the agent's own role."
        ),
    ),
    # 6. PutRolePolicy (inline admin policy)
    _EscalationPattern(
        technique="PutRolePolicy",
        required_actions=frozenset({"iam:PutRolePolicy"}),
        impact=(
            "Create an inline policy on any role granting Action:* Resource:*, "
            "effectively making the role an administrator."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitre_id="T1098.003",
        remediation=(
            "Remove iam:PutRolePolicy. Use SCPs to deny inline policy creation. "
            "Restrict to specific roles via resource ARN conditions."
        ),
        description=(
            "Inline policies bypass managed policy limits and cannot be restricted "
            "by permission boundaries applied to other identities."
        ),
    ),
    # 7. CreateRole + AttachRolePolicy (create new admin role)
    _EscalationPattern(
        technique="CreateRole with Admin Policy",
        required_actions=frozenset({"iam:CreateRole", "iam:AttachRolePolicy"}),
        impact=(
            "Create a new IAM role with a permissive trust policy (allowing self-assumption) "
            "and attach AdministratorAccess to it."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitre_id="T1136.003",
        remediation=(
            "Remove iam:CreateRole or restrict it with permission boundaries. "
            "Require MFA for role creation. Use SCPs to limit role creation."
        ),
        description=(
            "Agent creates a new role with a trust policy allowing itself to assume it, "
            "then attaches full admin permissions to that role."
        ),
    ),
    # 8. AssumeRole (cross-account admin)
    _EscalationPattern(
        technique="AssumeRole Cross-Account",
        required_actions=frozenset({"sts:AssumeRole"}),
        impact=(
            "Assume roles in other AWS accounts that may have higher privileges "
            "than the current account. Cross-account pivot."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1078.004",
        remediation=(
            "Restrict sts:AssumeRole to specific role ARNs via resource conditions. "
            "Require ExternalId for cross-account roles. Audit trust policies."
        ),
        description=(
            "If the agent can assume roles with wildcard resources, it may pivot to "
            "any role in any account that trusts this account/role."
        ),
    ),
    # 9. UpdateAssumeRolePolicy (modify trust to include attacker)
    _EscalationPattern(
        technique="UpdateAssumeRolePolicy",
        required_actions=frozenset({"iam:UpdateAssumeRolePolicy"}),
        impact=(
            "Modify any role's trust policy to allow the agent (or external entity) "
            "to assume it, even high-privilege roles."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitre_id="T1098.001",
        remediation=(
            "Remove iam:UpdateAssumeRolePolicy. Use SCPs to protect critical role trust "
            "policies. Monitor trust policy changes via CloudTrail."
        ),
        description=(
            "Trust policy modification is one of the most dangerous IAM actions because it "
            "allows hijacking any existing role regardless of its attached policies."
        ),
    ),
    # 10. Lambda CreateFunction + PassRole
    _EscalationPattern(
        technique="Lambda CreateFunction with PassRole",
        required_actions=frozenset({"lambda:CreateFunction", "iam:PassRole"}),
        impact=(
            "Create a Lambda function with an attacker-controlled execution role, "
            "then invoke it to execute arbitrary code with elevated permissions."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitre_id="T1548.002",
        remediation=(
            "Restrict lambda:CreateFunction to specific resource patterns. Limit "
            "iam:PassRole to Lambda-specific service roles with least privilege."
        ),
        description=(
            "Full code execution pipeline: create function with admin role, invoke it, "
            "and the function's code runs with the role's full permissions."
        ),
    ),
    # 11. Lambda UpdateFunctionCode (modify existing lambda)
    _EscalationPattern(
        technique="Lambda UpdateFunctionCode",
        required_actions=frozenset({"lambda:UpdateFunctionCode"}),
        impact=(
            "Modify the code of an existing Lambda function that has a high-privilege "
            "execution role. Next invocation runs attacker code as that role."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1525",
        remediation=(
            "Restrict lambda:UpdateFunctionCode to specific function ARNs. Enable "
            "Lambda code signing. Monitor for function code changes."
        ),
        description=(
            "Does not require PassRole — exploits whatever role the existing Lambda "
            "already has. Particularly dangerous for functions with broad permissions."
        ),
    ),
    # 12. Glue CreateDevEndpoint + PassRole
    _EscalationPattern(
        technique="Glue CreateDevEndpoint with PassRole",
        required_actions=frozenset({"glue:CreateDevEndpoint", "iam:PassRole"}),
        impact=(
            "Create a Glue development endpoint with an elevated role, providing "
            "an interactive environment (notebook/SSH) with that role's credentials."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1548.002",
        remediation=(
            "Remove glue:CreateDevEndpoint access. Migrate to Glue Studio/Interactive "
            "Sessions with tighter controls. Restrict PassRole to Glue service roles."
        ),
        description=(
            "Glue dev endpoints provide SSH access and notebook environments that "
            "execute with the passed role's full permissions."
        ),
    ),
    # 13. Glue UpdateDevEndpoint (SSH key injection)
    _EscalationPattern(
        technique="Glue UpdateDevEndpoint SSH Injection",
        required_actions=frozenset({"glue:UpdateDevEndpoint"}),
        impact=(
            "Inject an SSH public key into an existing Glue dev endpoint, gaining "
            "SSH access to the endpoint's environment and its IAM role credentials."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1098.004",
        remediation=(
            "Remove glue:UpdateDevEndpoint. Deprecate dev endpoints in favor of "
            "Glue Studio. Monitor for endpoint configuration changes."
        ),
        description=(
            "Does not require PassRole — uses the existing endpoint's role. Adding "
            "an SSH key provides persistent shell access."
        ),
    ),
    # 14. SageMaker CreateNotebookInstance + PassRole
    _EscalationPattern(
        technique="SageMaker Notebook with PassRole",
        required_actions=frozenset({"sagemaker:CreateNotebookInstance", "iam:PassRole"}),
        impact=(
            "Create a SageMaker notebook instance with a high-privilege role, "
            "providing interactive Jupyter access with that role's credentials."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1548.002",
        remediation=(
            "Restrict sagemaker:CreateNotebookInstance. Limit PassRole to SageMaker-specific "
            "roles with minimal permissions. Use VPC-only notebooks."
        ),
        description=(
            "SageMaker notebooks provide full interactive Python environments with "
            "access to the instance role's credentials via instance metadata."
        ),
    ),
    # 15. CloudFormation CreateStack + PassRole
    _EscalationPattern(
        technique="CloudFormation Stack with PassRole",
        required_actions=frozenset({"cloudformation:CreateStack", "iam:PassRole"}),
        impact=(
            "Deploy a CloudFormation stack with an admin service role that can create "
            "any AWS resource, including IAM entities with full access."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitre_id="T1548.002",
        remediation=(
            "Use CloudFormation StackSets with constraints. Restrict PassRole to specific "
            "CloudFormation service roles. Require stack review/approval workflows."
        ),
        description=(
            "CloudFormation with a permissive service role can create any resource the role "
            "allows, including new admin users, access keys, and backdoor roles."
        ),
    ),
    # 16. DataPipeline CreatePipeline + PassRole
    _EscalationPattern(
        technique="DataPipeline with PassRole",
        required_actions=frozenset({"datapipeline:CreatePipeline", "iam:PassRole"}),
        impact=(
            "Create a Data Pipeline that executes shell commands on EC2 instances "
            "using a high-privilege role."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1548.002",
        remediation=(
            "Remove datapipeline:CreatePipeline or migrate to Step Functions/MWAA. "
            "Restrict PassRole to pipeline-specific least-privilege roles."
        ),
        description=(
            "Data Pipeline activities can execute arbitrary shell commands on provisioned "
            "EC2 instances with the passed role's credentials."
        ),
    ),
    # 17. EC2 RunInstances + PassRole (instance profile escalation)
    _EscalationPattern(
        technique="EC2 Instance Profile Escalation",
        required_actions=frozenset({"ec2:RunInstances", "iam:PassRole"}),
        impact=(
            "Launch an EC2 instance with a high-privilege instance profile, then "
            "access instance metadata to obtain the role's credentials."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1548.002",
        remediation=(
            "Restrict ec2:RunInstances via conditions (ec2:InstanceType, VPC, etc.). "
            "Limit PassRole to specific instance profile roles. Require IMDSv2."
        ),
        description=(
            "The agent launches an instance with user data that extracts role credentials "
            "from the instance metadata service (IMDS)."
        ),
    ),
    # 18. SSM StartSession (direct EC2 access)
    _EscalationPattern(
        technique="SSM Session Manager Access",
        required_actions=frozenset({"ssm:StartSession"}),
        impact=(
            "Start an interactive shell session on any EC2 instance with SSM agent, "
            "gaining access to instance role credentials and local data."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1021.007",
        remediation=(
            "Restrict ssm:StartSession to specific instance IDs or tags. Require "
            "session logging. Use SSM Session Manager preferences for restrictions."
        ),
        description=(
            "SSM Session Manager provides shell access without SSH keys or security "
            "groups. Agent can access IMDS, local filesystems, and network."
        ),
    ),
    # 19. Bedrock CreateAgent + PassRole
    _EscalationPattern(
        technique="Bedrock Agent with PassRole",
        required_actions=frozenset({"bedrock:CreateAgent", "iam:PassRole"}),
        impact=(
            "Create a Bedrock agent with a high-privilege execution role that can "
            "access sensitive resources via action groups and knowledge bases."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1548.002",
        remediation=(
            "Restrict bedrock:CreateAgent. Limit PassRole to Bedrock-specific roles "
            "with minimal permissions. Audit agent action group configurations."
        ),
        description=(
            "Bedrock agents execute with their assigned role's permissions when "
            "invoking action groups, potentially accessing secrets, databases, etc."
        ),
    ),
    # 20. Bedrock UpdateAgent (modify agent's role/tools)
    _EscalationPattern(
        technique="Bedrock UpdateAgent Hijack",
        required_actions=frozenset({"bedrock:UpdateAgent"}),
        impact=(
            "Modify an existing Bedrock agent's configuration, including its execution "
            "role, action groups, or knowledge bases to escalate access."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1098",
        remediation=(
            "Restrict bedrock:UpdateAgent to specific agent resource ARNs. Enable "
            "CloudTrail logging for Bedrock API calls. Use SCPs for guardrails."
        ),
        description=(
            "Modifying a Bedrock agent's action groups can redirect its tool invocations "
            "to attacker-controlled endpoints or grant access to new resources."
        ),
    ),
    # 21. SageMaker CreateTrainingJob + PassRole
    _EscalationPattern(
        technique="SageMaker TrainingJob with PassRole",
        required_actions=frozenset({"sagemaker:CreateTrainingJob", "iam:PassRole"}),
        impact=(
            "Create a SageMaker training job with a high-privilege role, executing "
            "custom training code with that role's full permissions."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1548.002",
        remediation=(
            "Restrict sagemaker:CreateTrainingJob. Limit PassRole to SageMaker training "
            "roles with minimal data access. Use VPC mode for network isolation."
        ),
        description=(
            "Custom training containers execute arbitrary code with the training role's "
            "credentials. Can access S3, secrets, and network resources."
        ),
    ),
    # 22. SecretsManager credential chain (cross-account creds)
    _EscalationPattern(
        technique="SecretsManager Credential Chain",
        required_actions=frozenset({"secretsmanager:GetSecretValue"}),
        impact=(
            "Retrieve stored credentials (API keys, database passwords, cross-account "
            "access keys) from Secrets Manager, potentially enabling further escalation."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1555.006",
        remediation=(
            "Restrict secretsmanager:GetSecretValue to specific secret ARNs. Use "
            "resource policies on secrets. Rotate credentials regularly. "
            "Monitor GetSecretValue calls via CloudTrail."
        ),
        description=(
            "Many organizations store cross-account credentials, database passwords, "
            "and API keys in Secrets Manager. Accessing these can bootstrap further "
            "access outside the current permission boundary."
        ),
    ),
    # 23. PassRole + ECS (task role escalation)
    _EscalationPattern(
        technique="PassRole to ECS Task",
        required_actions=frozenset({"iam:PassRole"}),
        any_of_actions=frozenset({"ecs:RunTask", "ecs:CreateService", "ecs:StartTask"}),
        impact=(
            "Pass a high-privilege role to an ECS task, then execute container code "
            "with that role's credentials via task role."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1548.002",
        remediation=(
            "Restrict iam:PassRole with iam:PassedToService condition for ecs.amazonaws.com. "
            "Use task-specific least-privilege roles."
        ),
        description=(
            "ECS tasks receive their role credentials via the task metadata endpoint. "
            "Container code executes with whatever role is assigned to the task definition."
        ),
    ),
    # 24. PassRole + SageMaker (general)
    _EscalationPattern(
        technique="PassRole to SageMaker",
        required_actions=frozenset({"iam:PassRole"}),
        any_of_actions=frozenset({
            "sagemaker:CreateNotebookInstance",
            "sagemaker:CreateTrainingJob",
            "sagemaker:CreateProcessingJob",
            "sagemaker:CreateModel",
        }),
        impact=(
            "Pass a high-privilege role to any SageMaker compute resource, gaining "
            "code execution with that role's permissions."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1548.002",
        remediation=(
            "Use iam:PassedToService condition for sagemaker.amazonaws.com. Create "
            "dedicated SageMaker execution roles with minimal permissions."
        ),
        description=(
            "SageMaker services (notebooks, training, processing, endpoints) all execute "
            "with the passed role's credentials in various compute environments."
        ),
    ),
    # 25. CreateAccessKey credential generation
    _EscalationPattern(
        technique="IAM Access Key Generation",
        required_actions=frozenset({"iam:CreateAccessKey"}),
        impact=(
            "Create long-lived access keys for any IAM user, enabling persistent "
            "credential access outside the agent's session boundary."
        ),
        severity=EscalationSeverity.HIGH,
        mitre_id="T1098.001",
        remediation=(
            "Remove iam:CreateAccessKey permission from agent roles. Use SCPs to "
            "deny access key creation for service roles. Monitor CreateAccessKey "
            "calls via CloudTrail."
        ),
        description=(
            "An agent with iam:CreateAccessKey can generate long-lived credentials "
            "for IAM users, bypassing session-based controls and enabling persistent "
            "access that survives role assumption expiry."
        ),
    ),
]


# ─── Escalation Detector ─────────────────────────────────────────────────────


class EscalationDetector:
    """
    Detects privilege escalation paths available to AI agents.

    Scans an agent's effective permissions against a catalog of 22+ known
    AWS privilege escalation techniques and produces detailed findings with
    MITRE ATT&CK mappings and remediation guidance.

    Usage:
        detector = EscalationDetector()
        paths = detector.detect(agent, effective_permissions)
        for path in paths:
            print(f"{path.severity.value}: {path.technique} - {path.impact}")

    The detector can be extended with custom patterns via add_pattern().
    """

    def __init__(self) -> None:
        """Initialize the escalation detector with the built-in pattern catalog."""
        self._patterns: list[_EscalationPattern] = list(_ESCALATION_PATTERNS)
        logger.info(
            "EscalationDetector initialized with %d escalation patterns",
            len(self._patterns),
        )

    @property
    def pattern_count(self) -> int:
        """Return the number of registered escalation patterns."""
        return len(self._patterns)

    def add_pattern(
        self,
        technique: str,
        required_actions: set[str],
        impact: str,
        severity: EscalationSeverity,
        mitre_id: str,
        remediation: str,
        any_of_actions: set[str] | None = None,
        description: str = "",
    ) -> None:
        """
        Register a custom escalation pattern.

        Allows extending the detection catalog with organization-specific
        or newly-discovered escalation techniques.

        Args:
            technique: Name of the escalation technique.
            required_actions: Actions that must ALL be present.
            impact: Impact description.
            severity: Severity classification.
            mitre_id: MITRE ATT&CK technique ID.
            remediation: Remediation steps.
            any_of_actions: Optional actions where at least one must be present.
            description: Extended description.

        Raises:
            ValueError: If required fields are missing.
        """
        if not technique:
            raise ValueError("technique cannot be empty")
        if not required_actions:
            raise ValueError("required_actions cannot be empty")

        pattern = _EscalationPattern(
            technique=technique,
            required_actions=frozenset(required_actions),
            any_of_actions=frozenset(any_of_actions) if any_of_actions else frozenset(),
            impact=impact,
            severity=severity,
            mitre_id=mitre_id,
            remediation=remediation,
            description=description,
        )
        self._patterns.append(pattern)
        logger.info("Added custom escalation pattern: %s", technique)

    def detect(
        self,
        agent: AgentIdentity,
        effective_permissions: list[EffectivePermission],
    ) -> list[EscalationPath]:
        """
        Detect all known privilege escalation paths for an agent.

        Scans the agent's effective permissions against the full pattern catalog
        and returns all matching escalation paths sorted by severity.

        Args:
            agent: The agent identity to analyze.
            effective_permissions: The agent's resolved effective permissions.

        Returns:
            List of EscalationPath objects sorted by severity (CRITICAL first).

        Raises:
            ValueError: If agent or permissions are None.
        """
        if agent is None:
            raise ValueError("agent cannot be None")
        if effective_permissions is None:
            raise ValueError("effective_permissions cannot be None")

        logger.info(
            "Detecting escalation paths for agent '%s' (%s) with %d permissions",
            agent.name,
            agent.agent_id,
            len(effective_permissions),
        )

        # Filter to allowed permissions
        allowed = self._filter_allowed(effective_permissions)
        if not allowed:
            logger.info("No allowed permissions — no escalation paths possible")
            return []

        # Extract the set of available actions
        available_actions = self._extract_actions(allowed)
        # Also include wildcard-expanded actions
        expanded_actions = self._expand_wildcards(available_actions)

        detected: list[EscalationPath] = []

        try:
            for pattern in self._patterns:
                match_result = self._match_pattern(pattern, expanded_actions)
                if match_result is not None:
                    escalation_path = EscalationPath(
                        technique=pattern.technique,
                        required_permissions=list(pattern.required_actions | pattern.any_of_actions),
                        impact=pattern.impact,
                        severity=pattern.severity,
                        mitre_id=pattern.mitre_id,
                        remediation=pattern.remediation,
                        matched_permissions=match_result,
                        description=pattern.description,
                    )
                    detected.append(escalation_path)
                    logger.warning(
                        "Escalation detected for agent '%s': %s (%s) - %s",
                        agent.name,
                        pattern.technique,
                        pattern.severity.value,
                        pattern.mitre_id,
                    )

            # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
            severity_order = {
                EscalationSeverity.CRITICAL: 0,
                EscalationSeverity.HIGH: 1,
                EscalationSeverity.MEDIUM: 2,
                EscalationSeverity.LOW: 3,
            }
            detected.sort(key=lambda p: severity_order.get(p.severity, 99))

            logger.info(
                "Detected %d escalation paths for agent '%s' "
                "(CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d)",
                len(detected),
                agent.name,
                sum(1 for p in detected if p.severity == EscalationSeverity.CRITICAL),
                sum(1 for p in detected if p.severity == EscalationSeverity.HIGH),
                sum(1 for p in detected if p.severity == EscalationSeverity.MEDIUM),
                sum(1 for p in detected if p.severity == EscalationSeverity.LOW),
            )

            return detected

        except Exception as exc:
            logger.error(
                "Error detecting escalation paths for agent '%s': %s",
                agent.name,
                str(exc),
                exc_info=True,
            )
            raise

    def get_patterns_summary(self) -> list[dict[str, str]]:
        """
        Return a summary of all registered escalation patterns.

        Useful for documentation, reporting, and UI display.

        Returns:
            List of dictionaries with technique, severity, and mitre_id.
        """
        return [
            {
                "technique": p.technique,
                "severity": p.severity.value,
                "mitre_id": p.mitre_id,
                "required_actions": ", ".join(sorted(p.required_actions)),
            }
            for p in self._patterns
        ]

    # ─── Pattern Matching ─────────────────────────────────────────────────────

    def _match_pattern(
        self,
        pattern: _EscalationPattern,
        available_actions: set[str],
    ) -> list[str] | None:
        """
        Check if a pattern matches the available actions.

        A pattern matches when:
          1. ALL required_actions are present in available_actions, AND
          2. If any_of_actions is non-empty, at least ONE is present.

        Args:
            pattern: The escalation pattern to check.
            available_actions: Set of actions the agent can perform.

        Returns:
            List of matched action strings if pattern matches, None otherwise.
        """
        # Check all required actions are present
        matched = []
        for required_action in pattern.required_actions:
            if self._action_matches(required_action, available_actions):
                matched.append(required_action)
            else:
                return None  # Required action not available

        # Check any_of_actions (at least one must match, if specified)
        if pattern.any_of_actions:
            any_matched = False
            for any_action in pattern.any_of_actions:
                if self._action_matches(any_action, available_actions):
                    matched.append(any_action)
                    any_matched = True
            if not any_matched:
                return None

        return matched

    def _action_matches(self, target_action: str, available_actions: set[str]) -> bool:
        """
        Check if a target action is available, including wildcard matching.

        Handles:
          - Exact match: "iam:PassRole" in available
          - Service wildcard: "iam:*" covers "iam:PassRole"
          - Full wildcard: "*" covers everything

        Args:
            target_action: The action to check for.
            available_actions: Set of available actions.

        Returns:
            True if the target action is covered by available actions.
        """
        # Direct match
        if target_action in available_actions:
            return True

        # Full wildcard
        if "*" in available_actions:
            return True

        # Service-level wildcard (e.g., "iam:*" covers "iam:PassRole")
        if ":" in target_action:
            service = target_action.split(":")[0]
            if f"{service}:*" in available_actions:
                return True

        return False

    # ─── Helper Methods ───────────────────────────────────────────────────────

    def _filter_allowed(
        self, permissions: list[EffectivePermission]
    ) -> list[EffectivePermission]:
        """Filter to only ALLOWED and CONDITIONAL permissions."""
        return [
            p
            for p in permissions
            if p.effective_effect in (EffectiveEffect.ALLOWED, EffectiveEffect.CONDITIONAL)
        ]

    def _extract_actions(self, permissions: list[EffectivePermission]) -> set[str]:
        """Extract unique action strings from permissions."""
        return {p.action for p in permissions}

    def _expand_wildcards(self, actions: set[str]) -> set[str]:
        """
        Expand the action set to include wildcard coverage indicators.

        Does not enumerate all possible actions under a wildcard, but ensures
        the set contains the wildcard patterns themselves for matching.

        Args:
            actions: Original set of action strings.

        Returns:
            Expanded set including original actions and any wildcard patterns.
        """
        expanded = set(actions)

        # If full wildcard is present, it covers everything
        if "*" in expanded:
            return expanded

        # Service wildcards are already handled by _action_matches
        return expanded
