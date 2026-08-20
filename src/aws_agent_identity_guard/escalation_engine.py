"""AWS Agent Identity Guard - Privilege Escalation Detection Engine.

Production-grade engine for detecting known IAM privilege escalation
patterns and agent-specific escalation paths in AWS environments.

This module implements comprehensive detection of:
- Classic IAM privilege escalation techniques (20+ patterns)
- Agent-specific escalation paths (Bedrock, Lambda, SageMaker, etc.)
- Cross-account and cross-service escalation chains
- MITRE ATT&CK Cloud mapped techniques

The engine evaluates an agent's effective permissions against a catalog
of known escalation patterns and produces ranked reports with remediation
guidance.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
from typing import Any, Optional

from .models import (
    Agent,
    AttackStep,
    Finding,
    FindingCategory,
    Permission,
    PermissionEffect,
    PermissionSource,
    RiskScore,
    Severity,
    WorkloadType,
    Environment,
    SerializableMixin,
    _utcnow,
)


# =============================================================================
# Enumerations
# =============================================================================


@unique
class EscalationTechnique(str, Enum):
    """Known privilege escalation techniques in AWS IAM and agent workloads.

    Each value maps to a specific escalation pattern that can be exploited
    when an identity holds the required permissions.
    """

    # --- Classic IAM Escalation Patterns ---
    CREATE_POLICY_VERSION = "iam:CreatePolicyVersion"
    SET_DEFAULT_POLICY_VERSION = "iam:SetDefaultPolicyVersion"
    PASS_ROLE_LAMBDA_CREATE = "iam:PassRole+lambda:CreateFunction"
    PASS_ROLE_LAMBDA_UPDATE = "iam:PassRole+lambda:UpdateFunctionCode"
    PASS_ROLE_EC2_RUN_INSTANCES = "iam:PassRole+ec2:RunInstances"
    PASS_ROLE_ECS_CREATE = "iam:PassRole+ecs:CreateService"
    PASS_ROLE_CLOUDFORMATION = "iam:PassRole+cloudformation:CreateStack"
    PASS_ROLE_GLUE = "iam:PassRole+glue:CreateDevEndpoint"
    PASS_ROLE_DATAPIPELINE = "iam:PassRole+datapipeline:CreatePipeline"
    PASS_ROLE_SAGEMAKER = "iam:PassRole+sagemaker:CreateNotebookInstance"
    PASS_ROLE_CODEBUILD = "iam:PassRole+codebuild:CreateProject"
    ATTACH_USER_POLICY = "iam:AttachUserPolicy"
    ATTACH_ROLE_POLICY = "iam:AttachRolePolicy"
    ATTACH_GROUP_POLICY = "iam:AttachGroupPolicy"
    PUT_USER_POLICY = "iam:PutUserPolicy"
    PUT_ROLE_POLICY = "iam:PutRolePolicy"
    PUT_GROUP_POLICY = "iam:PutGroupPolicy"
    ADD_USER_TO_GROUP = "iam:AddUserToGroup"
    UPDATE_ASSUME_ROLE_POLICY = "iam:UpdateAssumeRolePolicy"
    CREATE_LOGIN_PROFILE = "iam:CreateLoginProfile"
    UPDATE_LOGIN_PROFILE = "iam:UpdateLoginProfile"
    CREATE_ACCESS_KEY = "iam:CreateAccessKey"
    ASSUME_ROLE_HIGHER_PRIV = "sts:AssumeRole"

    # --- Agent-Specific Escalation Patterns ---
    BEDROCK_TOOL_ROLE_ASSUMPTION = "bedrock:InvokeAgent+sts:AssumeRole"
    LAMBDA_INVOKE_CROSS_ROLE = "lambda:InvokeFunction+CrossRoleExecution"
    SAGEMAKER_ENDPOINT_ELEVATED = "sagemaker:InvokeEndpoint+ElevatedExecution"
    SECRETS_MANAGER_CREDENTIAL_THEFT = "secretsmanager:GetSecretValue+AuthAsAnother"
    S3_TERRAFORM_STATE_EXTRACTION = "s3:GetObject+TerraformStateCredentials"
    CROSS_ACCOUNT_ESCALATION = "sts:AssumeRole+CrossAccountEscalation"
    STEP_FUNCTIONS_ROLE_EXECUTION = "states:StartExecution+DifferentRole"
    ECS_METADATA_CREDENTIAL_EXTRACTION = "ecs:RunTask+MetadataCredentialExtraction"


@unique
class EscalationCategory(str, Enum):
    """High-level categorization for escalation techniques."""

    POLICY_MANIPULATION = "POLICY_MANIPULATION"
    ROLE_ASSUMPTION = "ROLE_ASSUMPTION"
    SERVICE_EXPLOITATION = "SERVICE_EXPLOITATION"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    CROSS_ACCOUNT = "CROSS_ACCOUNT"
    AGENT_SPECIFIC = "AGENT_SPECIFIC"


# =============================================================================
# Escalation Path Data Model
# =============================================================================


@dataclass
class EscalationPath(SerializableMixin):
    """A detected privilege escalation path from initial to escalated permissions.

    Represents a concrete technique an agent could exploit given its current
    permission set, along with severity assessment, MITRE mapping, and
    remediation guidance.
    """

    path_id: str
    technique: EscalationTechnique
    steps: list[str]
    initial_permissions: list[str]
    escalated_permissions: list[str]
    severity: Severity
    mitre_id: str
    description: str
    remediation: str
    prerequisites: list[str]
    category: EscalationCategory = EscalationCategory.POLICY_MANIPULATION
    likelihood: float = 0.5
    impact: float = 0.5
    detected_at: datetime = field(default_factory=_utcnow)

    def __post_init__(self) -> None:
        """Validate likelihood and impact ranges."""
        if not (0.0 <= self.likelihood <= 1.0):
            raise ValueError(
                f"likelihood must be between 0.0 and 1.0, got {self.likelihood}"
            )
        if not (0.0 <= self.impact <= 1.0):
            raise ValueError(
                f"impact must be between 0.0 and 1.0, got {self.impact}"
            )

    @property
    def risk_rating(self) -> float:
        """Combined risk rating (likelihood * impact)."""
        return self.likelihood * self.impact

    @classmethod
    def create(
        cls,
        technique: EscalationTechnique,
        steps: list[str],
        initial_permissions: list[str],
        escalated_permissions: list[str],
        severity: Severity,
        mitre_id: str,
        description: str,
        remediation: str,
        prerequisites: list[str],
        category: EscalationCategory = EscalationCategory.POLICY_MANIPULATION,
        likelihood: float = 0.5,
        impact: float = 0.5,
    ) -> EscalationPath:
        """Factory method with auto-generated path_id and timestamp."""
        path_id = f"EP-{uuid.uuid4().hex[:12].upper()}"
        return cls(
            path_id=path_id,
            technique=technique,
            steps=steps,
            initial_permissions=initial_permissions,
            escalated_permissions=escalated_permissions,
            severity=severity,
            mitre_id=mitre_id,
            description=description,
            remediation=remediation,
            prerequisites=prerequisites,
            category=category,
            likelihood=likelihood,
            impact=impact,
            detected_at=_utcnow(),
        )


# =============================================================================
# Escalation Pattern Definitions
# =============================================================================


@dataclass(frozen=True)
class _PatternDefinition:
    """Internal pattern definition used by the engine's detection catalog."""

    technique: EscalationTechnique
    required_permissions: frozenset[str]
    category: EscalationCategory
    severity: Severity
    mitre_id: str
    description: str
    remediation: str
    steps: tuple[str, ...]
    escalated_permissions: tuple[str, ...]
    prerequisites: tuple[str, ...]
    likelihood: float = 0.5
    impact: float = 0.8


# The canonical catalog of known escalation patterns.
_IAM_ESCALATION_PATTERNS: tuple[_PatternDefinition, ...] = (
    _PatternDefinition(
        technique=EscalationTechnique.CREATE_POLICY_VERSION,
        required_permissions=frozenset({"iam:CreatePolicyVersion"}),
        category=EscalationCategory.POLICY_MANIPULATION,
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        description=(
            "Agent can create a new policy version with administrator access and "
            "set it as the default, granting full AWS privileges."
        ),
        remediation=(
            "Remove iam:CreatePolicyVersion permission. Use AWS managed policies "
            "or implement SCP guardrails preventing policy version creation."
        ),
        steps=(
            "1. Create new policy version with Action:* Resource:*",
            "2. Set new version as default (if SetDefaultPolicyVersion also held)",
            "3. Agent now has full administrator access",
        ),
        escalated_permissions=("*:*",),
        prerequisites=("Must have iam:CreatePolicyVersion on a customer-managed policy",),
        likelihood=0.8,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.SET_DEFAULT_POLICY_VERSION,
        required_permissions=frozenset({"iam:SetDefaultPolicyVersion"}),
        category=EscalationCategory.POLICY_MANIPULATION,
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        description=(
            "Agent can activate a previously created permissive policy version, "
            "escalating privileges without creating new statements."
        ),
        remediation=(
            "Remove iam:SetDefaultPolicyVersion. Audit all policy versions for "
            "overly permissive statements. Enable AWS Config rule for policy changes."
        ),
        steps=(
            "1. List existing policy versions to find permissive ones",
            "2. Set the permissive version as default",
            "3. Agent assumes the elevated permissions of that version",
        ),
        escalated_permissions=("*:* (depending on dormant version content)",),
        prerequisites=(
            "A non-default policy version with broader permissions must exist",
        ),
        likelihood=0.6,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.ATTACH_USER_POLICY,
        required_permissions=frozenset({"iam:AttachUserPolicy"}),
        category=EscalationCategory.POLICY_MANIPULATION,
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        description=(
            "Agent can attach the AdministratorAccess managed policy (or any other) "
            "to its own IAM user or another user."
        ),
        remediation=(
            "Remove iam:AttachUserPolicy. Use permission boundaries to limit "
            "the maximum permissions that can be granted. Implement SCP to deny "
            "attachment of high-privilege policies."
        ),
        steps=(
            "1. Identify target IAM user (self or another)",
            "2. Attach arn:aws:iam::aws:policy/AdministratorAccess",
            "3. Target user now has full admin privileges",
        ),
        escalated_permissions=("*:*",),
        prerequisites=("iam:AttachUserPolicy on target user resource",),
        likelihood=0.8,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.ATTACH_ROLE_POLICY,
        required_permissions=frozenset({"iam:AttachRolePolicy"}),
        category=EscalationCategory.POLICY_MANIPULATION,
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        description=(
            "Agent can attach a managed policy with elevated permissions to its own "
            "role or another role it can assume."
        ),
        remediation=(
            "Remove iam:AttachRolePolicy or scope it to specific non-admin policies. "
            "Use permission boundaries on all roles. Implement SCP guardrails."
        ),
        steps=(
            "1. Identify target IAM role (own role or assumable role)",
            "2. Attach high-privilege managed policy to the role",
            "3. Assume or continue using the now-elevated role",
        ),
        escalated_permissions=("*:*",),
        prerequisites=("iam:AttachRolePolicy on target role resource",),
        likelihood=0.8,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.ATTACH_GROUP_POLICY,
        required_permissions=frozenset({"iam:AttachGroupPolicy"}),
        category=EscalationCategory.POLICY_MANIPULATION,
        severity=Severity.HIGH,
        mitre_id="T1098.001",
        description=(
            "Agent can attach a managed policy with elevated permissions to a group "
            "the agent's user belongs to."
        ),
        remediation=(
            "Remove iam:AttachGroupPolicy. Implement SCPs limiting policy attachment. "
            "Use permission boundaries on group members."
        ),
        steps=(
            "1. Identify target IAM group (group agent belongs to)",
            "2. Attach high-privilege managed policy to the group",
            "3. All group members (including agent) gain elevated permissions",
        ),
        escalated_permissions=("*:*",),
        prerequisites=(
            "iam:AttachGroupPolicy on target group",
            "Agent must be member of the target group",
        ),
        likelihood=0.7,
        impact=0.9,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PUT_USER_POLICY,
        required_permissions=frozenset({"iam:PutUserPolicy"}),
        category=EscalationCategory.POLICY_MANIPULATION,
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        description=(
            "Agent can create or update an inline policy on a user with unrestricted "
            "permissions (Action:*, Resource:*)."
        ),
        remediation=(
            "Remove iam:PutUserPolicy. Use permission boundaries. Monitor with "
            "CloudTrail and AWS Config for inline policy changes."
        ),
        steps=(
            "1. Craft inline policy document with Action:* Resource:*",
            "2. Apply inline policy to own user or target user via PutUserPolicy",
            "3. User now has full administrative permissions",
        ),
        escalated_permissions=("*:*",),
        prerequisites=("iam:PutUserPolicy on target user resource",),
        likelihood=0.8,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PUT_ROLE_POLICY,
        required_permissions=frozenset({"iam:PutRolePolicy"}),
        category=EscalationCategory.POLICY_MANIPULATION,
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        description=(
            "Agent can create or update an inline policy on its own role (or another "
            "assumable role) with unrestricted permissions."
        ),
        remediation=(
            "Remove iam:PutRolePolicy or scope to specific roles and policy names. "
            "Apply permission boundaries. Enable AWS Config rule "
            "iam-policy-no-statements-with-admin-access."
        ),
        steps=(
            "1. Craft inline policy document with full admin access",
            "2. Apply inline policy to own role via PutRolePolicy",
            "3. Role session now has full administrative access",
        ),
        escalated_permissions=("*:*",),
        prerequisites=("iam:PutRolePolicy on target role resource",),
        likelihood=0.8,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PUT_GROUP_POLICY,
        required_permissions=frozenset({"iam:PutGroupPolicy"}),
        category=EscalationCategory.POLICY_MANIPULATION,
        severity=Severity.HIGH,
        mitre_id="T1098.001",
        description=(
            "Agent can create an inline policy on a group it belongs to, granting "
            "all group members elevated permissions."
        ),
        remediation=(
            "Remove iam:PutGroupPolicy. Apply permission boundaries to group members. "
            "Monitor inline policy creation via CloudTrail."
        ),
        steps=(
            "1. Identify group the agent's user belongs to",
            "2. Create inline policy with elevated permissions on the group",
            "3. All group members gain the new permissions",
        ),
        escalated_permissions=("*:*",),
        prerequisites=(
            "iam:PutGroupPolicy on target group",
            "Agent user must be a member of the group",
        ),
        likelihood=0.7,
        impact=0.9,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.ADD_USER_TO_GROUP,
        required_permissions=frozenset({"iam:AddUserToGroup"}),
        category=EscalationCategory.POLICY_MANIPULATION,
        severity=Severity.HIGH,
        mitre_id="T1098.001",
        description=(
            "Agent can add its own user (or a controlled user) to an administrative "
            "group, inheriting all group policies."
        ),
        remediation=(
            "Remove iam:AddUserToGroup or scope to non-admin groups. "
            "Monitor group membership changes. Implement SCP preventing addition "
            "to critical groups."
        ),
        steps=(
            "1. Enumerate IAM groups to identify admin groups",
            "2. Add own user to the admin group via AddUserToGroup",
            "3. Inherit all policies attached to the admin group",
        ),
        escalated_permissions=("*:* (inherits admin group policies)",),
        prerequisites=(
            "iam:AddUserToGroup on target group",
            "An admin group must exist",
        ),
        likelihood=0.7,
        impact=0.9,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.UPDATE_ASSUME_ROLE_POLICY,
        required_permissions=frozenset({"iam:UpdateAssumeRolePolicy"}),
        category=EscalationCategory.ROLE_ASSUMPTION,
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        description=(
            "Agent can modify the trust policy of a high-privilege role to allow "
            "its own principal to assume it."
        ),
        remediation=(
            "Remove iam:UpdateAssumeRolePolicy. Implement SCP preventing trust policy "
            "modifications on sensitive roles. Use AWS Config to monitor trust policy "
            "changes."
        ),
        steps=(
            "1. Identify high-privilege role in the account",
            "2. Modify trust policy to add agent's principal as trusted entity",
            "3. Assume the now-accessible high-privilege role via sts:AssumeRole",
        ),
        escalated_permissions=("Full permissions of the target role",),
        prerequisites=(
            "iam:UpdateAssumeRolePolicy on target role",
            "sts:AssumeRole capability",
        ),
        likelihood=0.7,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.CREATE_LOGIN_PROFILE,
        required_permissions=frozenset({"iam:CreateLoginProfile"}),
        category=EscalationCategory.CREDENTIAL_THEFT,
        severity=Severity.HIGH,
        mitre_id="T1098.001",
        description=(
            "Agent can create a console login profile for an IAM user that "
            "doesn't have one, enabling console access with a known password."
        ),
        remediation=(
            "Remove iam:CreateLoginProfile. Monitor for login profile creation "
            "events in CloudTrail. Require MFA for all console access."
        ),
        steps=(
            "1. Identify IAM user without login profile (possibly admin user)",
            "2. Create login profile with known password",
            "3. Authenticate as that user via AWS Console",
        ),
        escalated_permissions=("Console access as target user",),
        prerequisites=(
            "iam:CreateLoginProfile on target user",
            "Target user must not have existing login profile",
        ),
        likelihood=0.6,
        impact=0.8,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.UPDATE_LOGIN_PROFILE,
        required_permissions=frozenset({"iam:UpdateLoginProfile"}),
        category=EscalationCategory.CREDENTIAL_THEFT,
        severity=Severity.HIGH,
        mitre_id="T1098.001",
        description=(
            "Agent can reset the console password for another IAM user, "
            "enabling console access with a known password."
        ),
        remediation=(
            "Remove iam:UpdateLoginProfile. Enforce MFA. Monitor password reset "
            "events in CloudTrail."
        ),
        steps=(
            "1. Identify target IAM user with elevated permissions",
            "2. Reset their console password via UpdateLoginProfile",
            "3. Authenticate as that user via AWS Console",
        ),
        escalated_permissions=("Console access as target user",),
        prerequisites=("iam:UpdateLoginProfile on target user",),
        likelihood=0.6,
        impact=0.8,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.CREATE_ACCESS_KEY,
        required_permissions=frozenset({"iam:CreateAccessKey"}),
        category=EscalationCategory.CREDENTIAL_THEFT,
        severity=Severity.HIGH,
        mitre_id="T1098.001",
        description=(
            "Agent can create programmatic access keys for another IAM user, "
            "enabling API access as that identity."
        ),
        remediation=(
            "Remove iam:CreateAccessKey or scope to own user only. Monitor "
            "access key creation in CloudTrail. Enforce access key rotation."
        ),
        steps=(
            "1. Identify target IAM user with elevated permissions",
            "2. Create new access key pair for that user",
            "3. Use the credentials to authenticate as the target user",
        ),
        escalated_permissions=("API access as target user",),
        prerequisites=("iam:CreateAccessKey on target user",),
        likelihood=0.7,
        impact=0.8,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.ASSUME_ROLE_HIGHER_PRIV,
        required_permissions=frozenset({"sts:AssumeRole"}),
        category=EscalationCategory.ROLE_ASSUMPTION,
        severity=Severity.HIGH,
        mitre_id="T1078.004",
        description=(
            "Agent can assume a role with higher privileges than its current "
            "session, escalating its effective permissions."
        ),
        remediation=(
            "Restrict sts:AssumeRole to specific role ARNs. Implement external ID "
            "requirements. Use permission boundaries on assumable roles. "
            "Audit trust policies."
        ),
        steps=(
            "1. Enumerate assumable roles (via trust policy or resource policies)",
            "2. Identify role with higher privileges than current session",
            "3. Assume the higher-privilege role via sts:AssumeRole",
        ),
        escalated_permissions=("Permissions of the assumed role",),
        prerequisites=(
            "sts:AssumeRole permission",
            "Trust policy of target role must allow assumption",
        ),
        likelihood=0.6,
        impact=0.9,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PASS_ROLE_LAMBDA_CREATE,
        required_permissions=frozenset({"iam:PassRole", "lambda:CreateFunction"}),
        category=EscalationCategory.SERVICE_EXPLOITATION,
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        description=(
            "Agent can create a Lambda function with an admin role and invoke it, "
            "executing arbitrary code with the elevated role's permissions."
        ),
        remediation=(
            "Remove iam:PassRole or scope to specific non-admin roles. "
            "Restrict lambda:CreateFunction. Use permission boundaries on Lambda "
            "execution roles."
        ),
        steps=(
            "1. Pass a high-privilege role to a new Lambda function",
            "2. Deploy function code that performs privileged operations",
            "3. Invoke the function to execute with the escalated role",
        ),
        escalated_permissions=("Permissions of the passed role",),
        prerequisites=(
            "iam:PassRole on a high-privilege role",
            "lambda:CreateFunction",
            "lambda:InvokeFunction (optional, can use event trigger)",
        ),
        likelihood=0.8,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PASS_ROLE_LAMBDA_UPDATE,
        required_permissions=frozenset({"iam:PassRole", "lambda:UpdateFunctionCode"}),
        category=EscalationCategory.SERVICE_EXPLOITATION,
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        description=(
            "Agent can update an existing Lambda function's code to execute "
            "privileged operations using the function's existing high-privilege role."
        ),
        remediation=(
            "Remove lambda:UpdateFunctionCode for sensitive functions. Implement "
            "code signing for Lambda. Monitor function code updates in CloudTrail."
        ),
        steps=(
            "1. Identify Lambda function with high-privilege execution role",
            "2. Update function code with malicious payload",
            "3. Invoke or wait for function trigger to execute elevated code",
        ),
        escalated_permissions=("Permissions of the Lambda execution role",),
        prerequisites=(
            "lambda:UpdateFunctionCode on target function",
            "Target function must have a high-privilege execution role",
        ),
        likelihood=0.7,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PASS_ROLE_EC2_RUN_INSTANCES,
        required_permissions=frozenset({"iam:PassRole", "ec2:RunInstances"}),
        category=EscalationCategory.SERVICE_EXPLOITATION,
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        description=(
            "Agent can launch an EC2 instance with a high-privilege instance profile, "
            "then access the metadata service to obtain elevated credentials."
        ),
        remediation=(
            "Remove iam:PassRole or restrict to specific instance profiles. "
            "Require IMDSv2 (token-based metadata). Use permission boundaries "
            "on instance roles."
        ),
        steps=(
            "1. Pass a high-privilege role as instance profile to new EC2 instance",
            "2. Connect to the instance (SSH or SSM)",
            "3. Query instance metadata service for role credentials",
            "4. Use credentials for privileged operations",
        ),
        escalated_permissions=("Permissions of the instance profile role",),
        prerequisites=(
            "iam:PassRole on a high-privilege role",
            "ec2:RunInstances",
            "Network access to launched instance",
        ),
        likelihood=0.7,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PASS_ROLE_ECS_CREATE,
        required_permissions=frozenset({"iam:PassRole", "ecs:CreateService"}),
        category=EscalationCategory.SERVICE_EXPLOITATION,
        severity=Severity.HIGH,
        mitre_id="T1098.001",
        description=(
            "Agent can create an ECS service/task with a high-privilege task role, "
            "executing container code with elevated permissions."
        ),
        remediation=(
            "Restrict iam:PassRole to specific ECS task roles. Implement "
            "permission boundaries. Monitor ECS task creation events."
        ),
        steps=(
            "1. Define task definition with high-privilege task role",
            "2. Create ECS service running the task definition",
            "3. Container code executes with the elevated task role",
        ),
        escalated_permissions=("Permissions of the ECS task role",),
        prerequisites=(
            "iam:PassRole on a high-privilege role",
            "ecs:CreateService or ecs:RunTask",
            "ecs:RegisterTaskDefinition",
        ),
        likelihood=0.6,
        impact=0.9,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PASS_ROLE_CLOUDFORMATION,
        required_permissions=frozenset({"iam:PassRole", "cloudformation:CreateStack"}),
        category=EscalationCategory.SERVICE_EXPLOITATION,
        severity=Severity.CRITICAL,
        mitre_id="T1098.001",
        description=(
            "Agent can create a CloudFormation stack with an admin service role, "
            "enabling creation of arbitrary resources including IAM entities."
        ),
        remediation=(
            "Remove iam:PassRole for CloudFormation roles. Use CloudFormation "
            "StackSets with guardrails. Implement SCP preventing stack creation "
            "with admin roles."
        ),
        steps=(
            "1. Create CloudFormation template with privileged resources (new admin role, etc.)",
            "2. Pass admin role to CloudFormation as the service role",
            "3. Stack creates resources using the admin role's permissions",
            "4. Assume newly created role or use created resources",
        ),
        escalated_permissions=("Arbitrary permissions via created resources",),
        prerequisites=(
            "iam:PassRole on a CloudFormation service role",
            "cloudformation:CreateStack",
        ),
        likelihood=0.7,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PASS_ROLE_GLUE,
        required_permissions=frozenset({"iam:PassRole", "glue:CreateDevEndpoint"}),
        category=EscalationCategory.SERVICE_EXPLOITATION,
        severity=Severity.HIGH,
        mitre_id="T1098.001",
        description=(
            "Agent can create a Glue Dev Endpoint with a high-privilege role, "
            "executing arbitrary code with that role's permissions."
        ),
        remediation=(
            "Remove glue:CreateDevEndpoint. Restrict iam:PassRole to specific "
            "Glue roles. Monitor Glue endpoint creation in CloudTrail."
        ),
        steps=(
            "1. Create Glue Dev Endpoint with high-privilege role",
            "2. Connect to the endpoint (SSH or notebook)",
            "3. Execute code with the attached role's credentials",
        ),
        escalated_permissions=("Permissions of the Glue execution role",),
        prerequisites=(
            "iam:PassRole on a high-privilege role",
            "glue:CreateDevEndpoint",
        ),
        likelihood=0.6,
        impact=0.9,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PASS_ROLE_DATAPIPELINE,
        required_permissions=frozenset({"iam:PassRole", "datapipeline:CreatePipeline"}),
        category=EscalationCategory.SERVICE_EXPLOITATION,
        severity=Severity.HIGH,
        mitre_id="T1098.001",
        description=(
            "Agent can create a Data Pipeline with a high-privilege role and "
            "execute arbitrary shell commands with that role's credentials."
        ),
        remediation=(
            "Remove datapipeline:CreatePipeline. Restrict iam:PassRole to "
            "specific pipeline roles. Deprecate Data Pipeline in favor of "
            "more controlled services."
        ),
        steps=(
            "1. Create Data Pipeline definition with ShellCommandActivity",
            "2. Pass high-privilege role to the pipeline",
            "3. Activate pipeline to execute commands with elevated credentials",
        ),
        escalated_permissions=("Permissions of the pipeline role",),
        prerequisites=(
            "iam:PassRole on a high-privilege role",
            "datapipeline:CreatePipeline",
            "datapipeline:PutPipelineDefinition",
        ),
        likelihood=0.5,
        impact=0.9,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PASS_ROLE_SAGEMAKER,
        required_permissions=frozenset({"iam:PassRole", "sagemaker:CreateNotebookInstance"}),
        category=EscalationCategory.SERVICE_EXPLOITATION,
        severity=Severity.HIGH,
        mitre_id="T1098.001",
        description=(
            "Agent can create a SageMaker notebook instance with a high-privilege "
            "role, executing arbitrary code with elevated permissions."
        ),
        remediation=(
            "Remove sagemaker:CreateNotebookInstance. Restrict iam:PassRole to "
            "specific SageMaker roles with least-privilege. Use VPC-only notebooks."
        ),
        steps=(
            "1. Create SageMaker notebook instance with high-privilege role",
            "2. Access notebook interface",
            "3. Execute code using the instance role's credentials",
        ),
        escalated_permissions=("Permissions of the SageMaker execution role",),
        prerequisites=(
            "iam:PassRole on a high-privilege role",
            "sagemaker:CreateNotebookInstance",
        ),
        likelihood=0.5,
        impact=0.9,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.PASS_ROLE_CODEBUILD,
        required_permissions=frozenset({"iam:PassRole", "codebuild:CreateProject"}),
        category=EscalationCategory.SERVICE_EXPLOITATION,
        severity=Severity.HIGH,
        mitre_id="T1098.001",
        description=(
            "Agent can create a CodeBuild project with a high-privilege service role "
            "and execute arbitrary build commands with that role's credentials."
        ),
        remediation=(
            "Remove codebuild:CreateProject or restrict iam:PassRole to specific "
            "CodeBuild roles. Monitor project creation. Use permission boundaries."
        ),
        steps=(
            "1. Create CodeBuild project with high-privilege service role",
            "2. Configure buildspec with commands to extract credentials or escalate",
            "3. Start build to execute commands with the service role",
        ),
        escalated_permissions=("Permissions of the CodeBuild service role",),
        prerequisites=(
            "iam:PassRole on a high-privilege role",
            "codebuild:CreateProject",
            "codebuild:StartBuild",
        ),
        likelihood=0.6,
        impact=0.9,
    ),
)

# Agent-specific escalation patterns
_AGENT_ESCALATION_PATTERNS: tuple[_PatternDefinition, ...] = (
    _PatternDefinition(
        technique=EscalationTechnique.BEDROCK_TOOL_ROLE_ASSUMPTION,
        required_permissions=frozenset({
            "bedrock:InvokeAgent",
            "sts:AssumeRole",
        }),
        category=EscalationCategory.AGENT_SPECIFIC,
        severity=Severity.CRITICAL,
        mitre_id="T1078.004",
        description=(
            "A Bedrock agent invokes a tool/action group that triggers role assumption "
            "to a higher-privilege role, enabling the agent to perform actions beyond "
            "its intended scope via tool-mediated escalation."
        ),
        remediation=(
            "Restrict Bedrock agent action groups to specific Lambda functions. "
            "Ensure Lambda execution roles follow least privilege. Implement "
            "guardrails on Bedrock agent to prevent role assumption actions. "
            "Use session policies to limit assumed role capabilities."
        ),
        steps=(
            "1. Bedrock agent receives prompt requiring privileged action",
            "2. Agent invokes action group backed by Lambda function",
            "3. Lambda function assumes a higher-privilege role",
            "4. Privileged operations executed under assumed role",
            "5. Results returned to agent, bypassing original permission scope",
        ),
        escalated_permissions=(
            "Permissions of the assumed role (potentially admin)",
        ),
        prerequisites=(
            "Bedrock agent with action groups configured",
            "Action group Lambda with sts:AssumeRole permission",
            "Trust policy allowing Lambda to assume target role",
        ),
        likelihood=0.7,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.LAMBDA_INVOKE_CROSS_ROLE,
        required_permissions=frozenset({"lambda:InvokeFunction"}),
        category=EscalationCategory.AGENT_SPECIFIC,
        severity=Severity.HIGH,
        mitre_id="T1078.004",
        description=(
            "Agent invokes a Lambda function that executes with a different "
            "(higher-privilege) execution role, effectively gaining access to "
            "that role's permissions through function invocation."
        ),
        remediation=(
            "Audit Lambda execution roles for least privilege. Restrict "
            "lambda:InvokeFunction to specific function ARNs. Implement "
            "input validation in Lambda functions. Use resource-based policies."
        ),
        steps=(
            "1. Agent identifies Lambda function with high-privilege execution role",
            "2. Agent invokes function with crafted payload",
            "3. Function executes with its (elevated) execution role",
            "4. Agent receives results of privileged operations",
        ),
        escalated_permissions=("Permissions of the Lambda execution role",),
        prerequisites=(
            "lambda:InvokeFunction on target function",
            "Target function must have a higher-privilege role",
            "Function must process agent-controlled input",
        ),
        likelihood=0.7,
        impact=0.9,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.SAGEMAKER_ENDPOINT_ELEVATED,
        required_permissions=frozenset({"sagemaker:InvokeEndpoint"}),
        category=EscalationCategory.AGENT_SPECIFIC,
        severity=Severity.HIGH,
        mitre_id="T1078.004",
        description=(
            "Agent invokes a SageMaker endpoint whose model container runs with "
            "elevated permissions, enabling code execution or data access beyond "
            "the agent's own permissions."
        ),
        remediation=(
            "Restrict SageMaker endpoint execution roles to minimum required. "
            "Use VPC endpoints. Implement input sanitization. Monitor invocation "
            "patterns for anomalies."
        ),
        steps=(
            "1. Agent identifies SageMaker endpoint with elevated role",
            "2. Agent sends crafted inference request to the endpoint",
            "3. Model container executes with elevated role permissions",
            "4. Exfiltrate data or perform privileged actions via model logic",
        ),
        escalated_permissions=("Permissions of the SageMaker execution role",),
        prerequisites=(
            "sagemaker:InvokeEndpoint on target endpoint",
            "Endpoint model must process agent-controlled input",
            "Endpoint role must have higher privileges than agent",
        ),
        likelihood=0.5,
        impact=0.8,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.SECRETS_MANAGER_CREDENTIAL_THEFT,
        required_permissions=frozenset({"secretsmanager:GetSecretValue"}),
        category=EscalationCategory.CREDENTIAL_THEFT,
        severity=Severity.CRITICAL,
        mitre_id="T1555",
        description=(
            "Agent retrieves credentials from Secrets Manager and uses them to "
            "authenticate as a different principal with higher privileges."
        ),
        remediation=(
            "Restrict secretsmanager:GetSecretValue to specific secret ARNs. "
            "Rotate secrets frequently. Use resource-based policies on secrets. "
            "Implement VPC endpoint policies. Monitor GetSecretValue calls."
        ),
        steps=(
            "1. Agent lists or guesses secret names/ARNs",
            "2. Agent retrieves secret value containing credentials",
            "3. Agent authenticates as the credential owner (API keys, passwords)",
            "4. Agent operates with the stolen identity's permissions",
        ),
        escalated_permissions=(
            "Permissions of the credential owner (potentially admin)",
        ),
        prerequisites=(
            "secretsmanager:GetSecretValue on secrets containing credentials",
            "Secrets must contain usable authentication material",
        ),
        likelihood=0.7,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.S3_TERRAFORM_STATE_EXTRACTION,
        required_permissions=frozenset({"s3:GetObject"}),
        category=EscalationCategory.CREDENTIAL_THEFT,
        severity=Severity.CRITICAL,
        mitre_id="T1552.001",
        description=(
            "Agent reads Terraform state files from S3 which may contain "
            "embedded credentials, secrets, or resource configurations that "
            "enable further escalation."
        ),
        remediation=(
            "Encrypt Terraform state with KMS. Restrict s3:GetObject to specific "
            "prefixes (exclude *.tfstate). Use state locking. Enable S3 access "
            "logging. Store sensitive values in Secrets Manager, not state."
        ),
        steps=(
            "1. Agent identifies S3 bucket containing Terraform state",
            "2. Agent retrieves .tfstate file via s3:GetObject",
            "3. Parse state for embedded credentials (RDS passwords, API keys)",
            "4. Use extracted credentials to authenticate as higher-privilege entity",
        ),
        escalated_permissions=(
            "Permissions of credentials embedded in Terraform state",
        ),
        prerequisites=(
            "s3:GetObject on bucket containing Terraform state",
            "State must contain embedded credentials or secrets",
        ),
        likelihood=0.6,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.CROSS_ACCOUNT_ESCALATION,
        required_permissions=frozenset({"sts:AssumeRole"}),
        category=EscalationCategory.CROSS_ACCOUNT,
        severity=Severity.CRITICAL,
        mitre_id="T1078.004",
        description=(
            "Agent assumes a role in another AWS account and exploits weaker "
            "security controls in that account to escalate privileges, then "
            "pivots back to the original account with elevated access."
        ),
        remediation=(
            "Implement external ID requirements for cross-account roles. "
            "Apply consistent SCPs across all accounts in the organization. "
            "Use AWS Organizations to enforce uniform security baselines. "
            "Restrict cross-account role trust policies."
        ),
        steps=(
            "1. Agent assumes cross-account role via sts:AssumeRole",
            "2. In target account, exploit weaker IAM controls to escalate",
            "3. Create or modify trust policy in target account",
            "4. Pivot back to source account with new elevated cross-account role",
        ),
        escalated_permissions=(
            "Admin permissions in target account",
            "Potentially elevated access in source account via back-pivot",
        ),
        prerequisites=(
            "sts:AssumeRole for cross-account role",
            "Target account must have weaker security controls",
            "Trust policy in target must allow source principal",
        ),
        likelihood=0.5,
        impact=1.0,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.STEP_FUNCTIONS_ROLE_EXECUTION,
        required_permissions=frozenset({"states:StartExecution"}),
        category=EscalationCategory.AGENT_SPECIFIC,
        severity=Severity.HIGH,
        mitre_id="T1078.004",
        description=(
            "Agent starts a Step Functions state machine execution that runs "
            "with a different (higher-privilege) IAM role, enabling privileged "
            "AWS API calls via state machine tasks."
        ),
        remediation=(
            "Restrict states:StartExecution to specific state machine ARNs. "
            "Audit state machine execution roles for least privilege. "
            "Implement input validation in state machines. Use resource policies."
        ),
        steps=(
            "1. Agent identifies Step Functions state machine with elevated role",
            "2. Agent starts execution with crafted input",
            "3. State machine executes tasks using its IAM role",
            "4. Tasks perform privileged operations (e.g., modify IAM, access data)",
        ),
        escalated_permissions=("Permissions of the Step Functions execution role",),
        prerequisites=(
            "states:StartExecution on target state machine",
            "State machine must have a higher-privilege execution role",
            "State machine must process agent-controlled input",
        ),
        likelihood=0.6,
        impact=0.9,
    ),
    _PatternDefinition(
        technique=EscalationTechnique.ECS_METADATA_CREDENTIAL_EXTRACTION,
        required_permissions=frozenset({"ecs:RunTask", "iam:PassRole"}),
        category=EscalationCategory.AGENT_SPECIFIC,
        severity=Severity.HIGH,
        mitre_id="T1552.005",
        description=(
            "Agent runs an ECS task configured to extract credentials from the "
            "task metadata endpoint (169.254.170.2), obtaining temporary "
            "credentials for the task's IAM role."
        ),
        remediation=(
            "Restrict ecs:RunTask and iam:PassRole to specific task definitions. "
            "Use awsvpc networking with security groups. Implement VPC endpoint "
            "policies. Monitor ECS task launches for anomalies."
        ),
        steps=(
            "1. Agent creates or uses task definition with high-privilege task role",
            "2. Agent runs ECS task (Fargate or EC2)",
            "3. Task container queries metadata endpoint for credentials",
            "4. Credentials exfiltrated to agent-controlled endpoint",
        ),
        escalated_permissions=("Temporary credentials of the ECS task role",),
        prerequisites=(
            "ecs:RunTask",
            "iam:PassRole on high-privilege task role",
            "Network access to exfiltrate credentials",
        ),
        likelihood=0.6,
        impact=0.9,
    ),
)


# =============================================================================
# Escalation Report
# =============================================================================


@dataclass
class EscalationReport(SerializableMixin):
    """Complete escalation analysis report for an agent.

    Contains all detected escalation paths ranked by severity and risk,
    along with summary statistics and remediation priorities.
    """

    report_id: str
    agent_id: str
    agent_name: str
    generated_at: datetime
    total_paths_detected: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    escalation_paths: list[EscalationPath]
    top_remediations: list[str]
    overall_risk: Severity
    summary: str

    @classmethod
    def create(
        cls,
        agent: Agent,
        paths: list[EscalationPath],
    ) -> EscalationReport:
        """Factory method to generate a report from detected paths."""
        critical = sum(1 for p in paths if p.severity == Severity.CRITICAL)
        high = sum(1 for p in paths if p.severity == Severity.HIGH)
        medium = sum(1 for p in paths if p.severity == Severity.MEDIUM)
        low = sum(1 for p in paths if p.severity == Severity.LOW)
        informational = sum(1 for p in paths if p.severity == Severity.INFORMATIONAL)

        # Determine overall risk
        if critical > 0:
            overall_risk = Severity.CRITICAL
        elif high > 0:
            overall_risk = Severity.HIGH
        elif medium > 0:
            overall_risk = Severity.MEDIUM
        elif low > 0:
            overall_risk = Severity.LOW
        else:
            overall_risk = Severity.INFORMATIONAL

        # Extract unique remediations, prioritized by severity
        sorted_paths = sorted(
            paths,
            key=lambda p: _severity_order(p.severity),
        )
        seen_remediations: set[str] = set()
        top_remediations: list[str] = []
        for path in sorted_paths:
            if path.remediation not in seen_remediations:
                seen_remediations.add(path.remediation)
                top_remediations.append(path.remediation)
                if len(top_remediations) >= 10:
                    break

        summary = (
            f"Detected {len(paths)} escalation path(s) for agent '{agent.name}': "
            f"{critical} critical, {high} high, {medium} medium, "
            f"{low} low, {informational} informational."
        )

        return cls(
            report_id=f"ER-{uuid.uuid4().hex[:12].upper()}",
            agent_id=agent.agent_id,
            agent_name=agent.name,
            generated_at=_utcnow(),
            total_paths_detected=len(paths),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            informational_count=informational,
            escalation_paths=sorted_paths,
            top_remediations=top_remediations,
            overall_risk=overall_risk,
            summary=summary,
        )


# =============================================================================
# Helper Functions
# =============================================================================


def _severity_order(severity: Severity) -> int:
    """Return numeric order for severity (lower = more severe)."""
    order_map = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFORMATIONAL: 4,
    }
    return order_map.get(severity, 5)


def _extract_actions_from_policies(
    identity_policies: list[dict[str, Any]],
) -> set[str]:
    """Extract all allowed actions from identity policy documents.

    Parses IAM policy document structure to extract action strings
    from Allow statements. Handles both raw policy documents and
    wrapped format (with PolicyName/PolicyDocument keys).

    Args:
        identity_policies: List of IAM policy documents or policy wrappers.

    Returns:
        Set of action strings the agent is allowed to perform.
    """
    actions: set[str] = set()

    for policy_item in identity_policies:
        # Handle wrapped format: {"PolicyName": ..., "PolicyDocument": {...}}
        if "PolicyDocument" in policy_item:
            policy_doc = policy_item["PolicyDocument"]
        else:
            policy_doc = policy_item

        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect", "").upper() != "ALLOW":
                continue

            stmt_actions = statement.get("Action", [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]

            for action in stmt_actions:
                actions.add(action.lower())

    return actions


def _action_matches(agent_action: str, pattern_action: str) -> bool:
    """Check if an agent's action matches a required pattern action.

    Supports wildcard matching (e.g., 'iam:*' matches 'iam:CreatePolicyVersion').

    Args:
        agent_action: The action the agent has (may include wildcards).
        pattern_action: The specific action required by the escalation pattern.

    Returns:
        True if the agent action satisfies the pattern requirement.
    """
    agent_lower = agent_action.lower()
    pattern_lower = pattern_action.lower()

    # Exact match
    if agent_lower == pattern_lower:
        return True

    # Full wildcard
    if agent_lower == "*" or agent_lower == "*:*":
        return True

    # Service-level wildcard (e.g., "iam:*" matches "iam:CreatePolicyVersion")
    if agent_lower.endswith(":*"):
        service_prefix = agent_lower[:-1]  # "iam:"
        if pattern_lower.startswith(service_prefix):
            return True

    # Suffix wildcard (e.g., "iam:Create*" matches "iam:CreatePolicyVersion")
    if "*" in agent_lower:
        prefix = agent_lower.split("*")[0]
        if pattern_lower.startswith(prefix):
            return True

    return False


def _agent_has_permission(agent_actions: set[str], required_action: str) -> bool:
    """Check if the agent's action set satisfies a required permission.

    Args:
        agent_actions: Set of actions the agent is allowed to perform.
        required_action: The specific action required by an escalation pattern.

    Returns:
        True if any of the agent's actions satisfy the requirement.
    """
    for agent_action in agent_actions:
        if _action_matches(agent_action, required_action):
            return True
    return False


def _check_pattern_match(
    agent_actions: set[str],
    pattern: _PatternDefinition,
) -> bool:
    """Determine if an agent's permissions satisfy all requirements of a pattern.

    Args:
        agent_actions: Set of actions the agent is allowed to perform.
        pattern: The escalation pattern to check against.

    Returns:
        True if the agent has all required permissions for this pattern.
    """
    for required in pattern.required_permissions:
        if not _agent_has_permission(agent_actions, required):
            return False
    return True


# =============================================================================
# Escalation Engine
# =============================================================================


class EscalationEngine:
    """Privilege escalation detection engine for AWS agent workloads.

    Analyzes an agent's effective permissions against a comprehensive catalog
    of known IAM escalation patterns and agent-specific escalation paths.
    Produces ranked reports with actionable remediation guidance.

    The engine detects:
    - Classic IAM privilege escalation (policy manipulation, role assumption)
    - Service-mediated escalation via iam:PassRole
    - Agent-specific escalation (Bedrock, Lambda, SageMaker, etc.)
    - Cross-account and cross-service escalation chains
    - Credential theft and extraction patterns

    Usage:
        engine = EscalationEngine()
        paths = engine.detect_escalation_paths(agent)
        report = engine.generate_report(agent)

    Attributes:
        _iam_patterns: Catalog of classic IAM escalation patterns.
        _agent_patterns: Catalog of agent-specific escalation patterns.
        _detected_paths: Cache of last detection results per agent.
    """

    def __init__(self) -> None:
        """Initialize the escalation engine with pattern catalogs."""
        self._iam_patterns: tuple[_PatternDefinition, ...] = _IAM_ESCALATION_PATTERNS
        self._agent_patterns: tuple[_PatternDefinition, ...] = _AGENT_ESCALATION_PATTERNS
        self._detected_paths: dict[str, list[EscalationPath]] = {}

    @property
    def total_patterns(self) -> int:
        """Total number of escalation patterns in the detection catalog."""
        return len(self._iam_patterns) + len(self._agent_patterns)

    @property
    def iam_pattern_count(self) -> int:
        """Number of classic IAM escalation patterns."""
        return len(self._iam_patterns)

    @property
    def agent_pattern_count(self) -> int:
        """Number of agent-specific escalation patterns."""
        return len(self._agent_patterns)

    def detect_escalation_paths(self, agent: Agent) -> list[EscalationPath]:
        """Detect all applicable privilege escalation paths for an agent.

        Evaluates the agent's identity policies against the full catalog of
        known escalation patterns (IAM + agent-specific) and returns all
        paths where the agent holds sufficient permissions.

        Args:
            agent: The agent identity to analyze.

        Returns:
            List of detected EscalationPath objects, sorted by severity
            (critical first).

        Example:
            >>> engine = EscalationEngine()
            >>> paths = engine.detect_escalation_paths(agent)
            >>> for path in paths:
            ...     print(f"{path.severity.value}: {path.technique.value}")
        """
        agent_actions = _extract_actions_from_policies(agent.identity_policies)
        detected: list[EscalationPath] = []

        # Check all IAM patterns
        for pattern in self._iam_patterns:
            if _check_pattern_match(agent_actions, pattern):
                path = self._build_escalation_path(agent, pattern)
                detected.append(path)

        # Check all agent-specific patterns
        for pattern in self._agent_patterns:
            if _check_pattern_match(agent_actions, pattern):
                path = self._build_escalation_path(agent, pattern)
                detected.append(path)

        # Apply environment-based severity adjustment
        detected = [
            self._adjust_severity_for_environment(path, agent)
            for path in detected
        ]

        # Sort by severity (critical first), then by risk rating
        detected.sort(
            key=lambda p: (_severity_order(p.severity), -p.risk_rating),
        )

        # Cache results
        self._detected_paths[agent.agent_id] = detected

        return detected

    def classify_escalation_risk(self, path: EscalationPath) -> Severity:
        """Classify the overall risk severity of an escalation path.

        Uses a multi-factor assessment considering:
        - Base severity of the technique
        - Likelihood of successful exploitation
        - Impact if exploited
        - Number of prerequisites (more = harder to exploit)
        - Whether the path involves cross-account escalation

        Args:
            path: The escalation path to classify.

        Returns:
            The assessed Severity level for the path.

        Example:
            >>> severity = engine.classify_escalation_risk(path)
            >>> print(severity.value)
            'CRITICAL'
        """
        # Start with base severity score
        base_scores = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFORMATIONAL: 0.1,
        }
        base_score = base_scores.get(path.severity, 0.5)

        # Factor in likelihood and impact
        risk_factor = path.likelihood * path.impact

        # Prerequisite complexity reduces effective risk
        prereq_factor = max(0.5, 1.0 - (len(path.prerequisites) * 0.1))

        # Cross-account paths are inherently higher risk
        cross_account_bonus = 0.1 if path.category == EscalationCategory.CROSS_ACCOUNT else 0.0

        # Combined score
        combined = (base_score * 0.4) + (risk_factor * 0.4) + (prereq_factor * 0.1) + cross_account_bonus

        # Map back to severity
        if combined >= 0.8:
            return Severity.CRITICAL
        elif combined >= 0.6:
            return Severity.HIGH
        elif combined >= 0.4:
            return Severity.MEDIUM
        elif combined >= 0.2:
            return Severity.LOW
        else:
            return Severity.INFORMATIONAL

    def generate_report(self, agent: Agent) -> EscalationReport:
        """Generate a comprehensive escalation analysis report for an agent.

        Runs full detection if not already cached, then produces a ranked
        report with all paths, summary statistics, and prioritized
        remediation guidance.

        Args:
            agent: The agent identity to generate the report for.

        Returns:
            EscalationReport with all detected paths ranked by severity.

        Example:
            >>> report = engine.generate_report(agent)
            >>> print(report.summary)
            >>> for remediation in report.top_remediations:
            ...     print(f"  - {remediation}")
        """
        # Use cached results if available, otherwise detect
        if agent.agent_id in self._detected_paths:
            paths = self._detected_paths[agent.agent_id]
        else:
            paths = self.detect_escalation_paths(agent)

        return EscalationReport.create(agent=agent, paths=paths)

    def get_patterns_by_category(
        self, category: EscalationCategory
    ) -> list[_PatternDefinition]:
        """Retrieve all patterns belonging to a specific category.

        Args:
            category: The escalation category to filter by.

        Returns:
            List of pattern definitions matching the category.
        """
        all_patterns = list(self._iam_patterns) + list(self._agent_patterns)
        return [p for p in all_patterns if p.category == category]

    def get_patterns_by_severity(
        self, severity: Severity
    ) -> list[_PatternDefinition]:
        """Retrieve all patterns of a specific severity level.

        Args:
            severity: The severity level to filter by.

        Returns:
            List of pattern definitions matching the severity.
        """
        all_patterns = list(self._iam_patterns) + list(self._agent_patterns)
        return [p for p in all_patterns if p.severity == severity]

    def check_specific_technique(
        self, agent: Agent, technique: EscalationTechnique
    ) -> Optional[EscalationPath]:
        """Check if an agent is vulnerable to a specific escalation technique.

        Args:
            agent: The agent identity to check.
            technique: The specific technique to evaluate.

        Returns:
            EscalationPath if vulnerable, None otherwise.
        """
        agent_actions = _extract_actions_from_policies(agent.identity_policies)
        all_patterns = list(self._iam_patterns) + list(self._agent_patterns)

        for pattern in all_patterns:
            if pattern.technique == technique:
                if _check_pattern_match(agent_actions, pattern):
                    path = self._build_escalation_path(agent, pattern)
                    return self._adjust_severity_for_environment(path, agent)
                return None

        return None

    def get_mitre_mapping(self) -> dict[str, list[EscalationTechnique]]:
        """Get mapping of MITRE ATT&CK IDs to escalation techniques.

        Returns:
            Dictionary mapping MITRE IDs to lists of techniques.
        """
        mapping: dict[str, list[EscalationTechnique]] = {}
        all_patterns = list(self._iam_patterns) + list(self._agent_patterns)

        for pattern in all_patterns:
            if pattern.mitre_id not in mapping:
                mapping[pattern.mitre_id] = []
            mapping[pattern.mitre_id].append(pattern.technique)

        return mapping

    def clear_cache(self) -> None:
        """Clear the internal detection results cache."""
        self._detected_paths.clear()

    # -------------------------------------------------------------------------
    # Private Methods
    # -------------------------------------------------------------------------

    def _build_escalation_path(
        self,
        agent: Agent,
        pattern: _PatternDefinition,
    ) -> EscalationPath:
        """Build an EscalationPath from a matched pattern.

        Args:
            agent: The agent whose permissions matched.
            pattern: The pattern definition that was matched.

        Returns:
            Fully populated EscalationPath instance.
        """
        return EscalationPath.create(
            technique=pattern.technique,
            steps=list(pattern.steps),
            initial_permissions=sorted(pattern.required_permissions),
            escalated_permissions=list(pattern.escalated_permissions),
            severity=pattern.severity,
            mitre_id=pattern.mitre_id,
            description=pattern.description,
            remediation=pattern.remediation,
            prerequisites=list(pattern.prerequisites),
            category=pattern.category,
            likelihood=pattern.likelihood,
            impact=pattern.impact,
        )

    def _adjust_severity_for_environment(
        self,
        path: EscalationPath,
        agent: Agent,
    ) -> EscalationPath:
        """Adjust escalation path severity based on agent environment.

        Production environments increase severity by one level.
        Dev environments may decrease severity for informational purposes.

        Args:
            path: The escalation path to adjust.
            agent: The agent providing environment context.

        Returns:
            The path with adjusted severity (may be the same object if no change).
        """
        if agent.environment == Environment.PRODUCTION:
            # In production, escalate severity one level (unless already critical)
            escalation_map = {
                Severity.HIGH: Severity.CRITICAL,
                Severity.MEDIUM: Severity.HIGH,
                Severity.LOW: Severity.MEDIUM,
                Severity.INFORMATIONAL: Severity.LOW,
            }
            new_severity = escalation_map.get(path.severity, path.severity)
            if new_severity != path.severity:
                path.severity = new_severity
        elif agent.environment == Environment.DEV:
            # In dev, reduce severity one level (unless already informational)
            reduction_map = {
                Severity.CRITICAL: Severity.CRITICAL,  # Never reduce critical
                Severity.HIGH: Severity.MEDIUM,
                Severity.MEDIUM: Severity.LOW,
                Severity.LOW: Severity.INFORMATIONAL,
            }
            new_severity = reduction_map.get(path.severity, path.severity)
            if new_severity != path.severity:
                path.severity = new_severity

        return path

    def __repr__(self) -> str:
        """Return string representation of the engine."""
        return (
            f"EscalationEngine("
            f"iam_patterns={self.iam_pattern_count}, "
            f"agent_patterns={self.agent_pattern_count}, "
            f"total={self.total_patterns})"
        )
