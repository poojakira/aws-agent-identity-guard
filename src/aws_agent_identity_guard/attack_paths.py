"""
Attack Path Analysis Engine for AWS Agent Identity Guard.

This module provides a graph-based attack path discovery and analysis engine
that identifies complete attack chains  -  not just individual findings  -  across
AWS AI agent permissions and resource configurations.

Attack chains represent multi-step exploitation paths such as:
    Agent -> PassRole -> Role B -> Lambda -> S3 -> Secret

Each step captures the source, action, target, conditions, and risk contribution,
enabling defenders to prioritize remediation based on full chain impact.

The engine uses BFS/DFS with cycle detection to enumerate all reachable attack
paths from a given agent's effective permissions, then ranks them by likelihood,
impact, and exploitability.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .models import (
    Agent,
    AttackPath,
    AttackStep,
    DataClassification,
    Environment,
    RiskScore,
    Severity,
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class MitreTechnique(str, Enum):
    """MITRE ATT&CK technique identifiers relevant to AWS agent attack paths."""

    VALID_ACCOUNTS = "T1078"
    ABUSE_ELEVATION_CONTROL = "T1548"
    ACCESS_TOKEN_MANIPULATION = "T1134"
    CREDENTIALS_FROM_PASSWORD_STORES = "T1555"
    UNSECURED_CREDENTIALS = "T1552"
    CLOUD_INFRASTRUCTURE_DISCOVERY = "T1580"
    PERMISSION_GROUPS_DISCOVERY = "T1069"
    LATERAL_MOVEMENT_REMOTE_SERVICES = "T1021"
    EXECUTION_SERVERLESS = "T1648"
    DATA_FROM_CLOUD_STORAGE = "T1530"
    STEAL_APPLICATION_ACCESS_TOKEN = "T1528"
    IMPERSONATION = "T1656"
    COMMAND_SCRIPTING_INTERPRETER = "T1059"
    EXPLOITATION_FOR_PRIVILEGE_ESCALATION = "T1068"
    MODIFY_CLOUD_COMPUTE_INFRA = "T1578"


class AttackPatternCategory(str, Enum):
    """Categories of known attack patterns."""

    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    ARBITRARY_EXECUTION = "arbitrary_execution"
    PERSISTENCE = "persistence"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphNode:
    """A node in the attack graph representing an AWS resource or principal.

    Attributes:
        node_id: Unique identifier for the node (ARN or logical name).
        node_type: Type of node (e.g., 'agent', 'role', 'lambda', 's3', 'secret').
        properties: Additional metadata about the node.
    """

    node_id: str
    node_type: str
    properties: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.node_id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GraphNode):
            return NotImplemented
        return self.node_id == other.node_id


@dataclass
class GraphEdge:
    """An edge in the attack graph representing an action between nodes.

    Attributes:
        source: The source node of the action.
        target: The target node of the action.
        action: The AWS action enabling this transition (e.g., 'iam:PassRole').
        permission_required: The IAM permission required for this edge.
        conditions: Conditions that must hold for this edge to be traversable.
        risk_weight: Numeric weight representing risk contribution (0.0 - 1.0).
    """

    source: GraphNode
    target: GraphNode
    action: str
    permission_required: str
    conditions: list[str] = field(default_factory=list)
    risk_weight: float = 0.5


@dataclass
class AttackPatternTemplate:
    """A known attack pattern template used for matching against agent permissions.

    Attributes:
        pattern_id: Unique identifier for the pattern.
        name: Human-readable name for the attack pattern.
        category: The category this pattern belongs to.
        description: Detailed description of how the attack works.
        required_permissions: Permissions the agent must have for this pattern to apply.
        steps_template: Ordered list of step descriptors forming the attack chain.
        mitre_technique_ids: Associated MITRE ATT&CK technique IDs.
        base_likelihood: Base likelihood score (0.0 - 1.0) before condition adjustments.
        base_impact: Base impact score (0.0 - 1.0) representing worst-case outcome.
        base_exploitability: Base exploitability score (0.0 - 1.0).
        remediation: Recommended remediation steps.
        environment_multipliers: Score multipliers per environment.
    """

    pattern_id: str
    name: str
    category: AttackPatternCategory
    description: str
    required_permissions: list[str]
    steps_template: list[dict[str, str]]
    mitre_technique_ids: list[str]
    base_likelihood: float
    base_impact: float
    base_exploitability: float
    remediation: str
    environment_multipliers: dict[str, float] = field(default_factory=dict)


@dataclass
class DiscoveredAttackStep:
    """A single step in a discovered attack path.

    Attributes:
        step_number: Ordinal position in the attack chain (1-indexed).
        source_node: The node initiating this step.
        action: The AWS action or technique used.
        target_node: The node being targeted.
        permission_required: The IAM permission enabling this step.
        condition: Conditions required for successful execution.
        risk_contribution: Risk score contribution of this step (0.0 - 1.0).
        description: Human-readable description of what this step achieves.
    """

    step_number: int
    source_node: str
    action: str
    target_node: str
    permission_required: str
    condition: str
    risk_contribution: float
    description: str


@dataclass
class DiscoveredAttackPath:
    """A complete attack path discovered through graph traversal.

    Attributes:
        path_id: Unique identifier for this path.
        steps: Ordered list of attack steps forming the chain.
        source_agent: The agent (starting point) of the attack path.
        target_resource: The final resource compromised at the end of the chain.
        likelihood_score: Probability the attack can be executed (0.0 - 1.0).
        impact_score: Severity of the outcome if exploited (0.0 - 1.0).
        exploitability_score: Ease of exploitation (0.0 - 1.0).
        combined_score: Weighted combination of all scores (0.0 - 1.0).
        description: Summary of the attack path.
        mitre_technique_ids: All MITRE ATT&CK techniques involved.
        remediation: Recommended remediation actions.
        severity: Computed severity based on combined score.
        pattern_match: The matched attack pattern template, if any.
    """

    path_id: str
    steps: list[DiscoveredAttackStep]
    source_agent: str
    target_resource: str
    likelihood_score: float
    impact_score: float
    exploitability_score: float
    combined_score: float
    description: str
    mitre_technique_ids: list[str]
    remediation: str
    severity: Severity = Severity.MEDIUM
    pattern_match: Optional[str] = None


@dataclass
class PathReport:
    """A complete attack path analysis report.

    Attributes:
        report_id: Unique identifier for this report.
        agent_id: The agent that was analyzed.
        total_paths_discovered: Total number of attack paths found.
        critical_paths: Paths with CRITICAL severity.
        high_paths: Paths with HIGH severity.
        medium_paths: Paths with MEDIUM severity.
        low_paths: Paths with LOW severity.
        paths_by_category: Paths grouped by attack category.
        top_recommendations: Priority-ordered remediation recommendations.
        summary: Executive summary of findings.
    """

    report_id: str
    agent_id: str
    total_paths_discovered: int
    critical_paths: list[DiscoveredAttackPath]
    high_paths: list[DiscoveredAttackPath]
    medium_paths: list[DiscoveredAttackPath]
    low_paths: list[DiscoveredAttackPath]
    paths_by_category: dict[str, list[DiscoveredAttackPath]]
    top_recommendations: list[str]
    summary: str


# ---------------------------------------------------------------------------
# Attack Pattern Templates Registry
# ---------------------------------------------------------------------------

KNOWN_ATTACK_PATTERNS: list[AttackPatternTemplate] = [
    # 1. PassRole chain to admin
    AttackPatternTemplate(
        pattern_id="PASS_ROLE_ADMIN_CHAIN",
        name="PassRole to Administrative Role",
        category=AttackPatternCategory.PRIVILEGE_ESCALATION,
        description=(
            "Agent can pass an administrative role to a service, effectively "
            "escalating to full admin privileges via the assumed role."
        ),
        required_permissions=["iam:PassRole"],
        steps_template=[
            {"action": "iam:PassRole", "target_type": "role", "desc": "Pass admin role to service"},
            {"action": "assume_via_service", "target_type": "service", "desc": "Service assumes passed role"},
            {"action": "admin_access", "target_type": "any", "desc": "Full admin actions available"},
        ],
        mitre_technique_ids=[MitreTechnique.ABUSE_ELEVATION_CONTROL, MitreTechnique.ACCESS_TOKEN_MANIPULATION],
        base_likelihood=0.8,
        base_impact=1.0,
        base_exploitability=0.9,
        remediation=(
            "Restrict iam:PassRole to specific non-admin roles. Use resource-based "
            "conditions to limit which roles can be passed."
        ),
        environment_multipliers={"production": 1.5, "staging": 1.2, "development": 0.8},
    ),
    # 2. Lambda privilege escalation
    AttackPatternTemplate(
        pattern_id="LAMBDA_PRIV_ESC",
        name="Lambda Privilege Escalation",
        category=AttackPatternCategory.PRIVILEGE_ESCALATION,
        description=(
            "Agent invokes or modifies a Lambda function that has an execution role "
            "with higher privileges than the agent, escalating access."
        ),
        required_permissions=["lambda:InvokeFunction", "lambda:UpdateFunctionCode"],
        steps_template=[
            {"action": "lambda:UpdateFunctionCode", "target_type": "lambda", "desc": "Modify Lambda code"},
            {"action": "lambda:InvokeFunction", "target_type": "lambda", "desc": "Invoke modified Lambda"},
            {"action": "sts:AssumeRole", "target_type": "role", "desc": "Lambda assumes its execution role"},
            {"action": "privileged_action", "target_type": "any", "desc": "Execute privileged operations"},
        ],
        mitre_technique_ids=[MitreTechnique.EXECUTION_SERVERLESS, MitreTechnique.ABUSE_ELEVATION_CONTROL],
        base_likelihood=0.7,
        base_impact=0.9,
        base_exploitability=0.85,
        remediation=(
            "Limit lambda:UpdateFunctionCode and lambda:UpdateFunctionConfiguration. "
            "Ensure Lambda execution roles follow least privilege."
        ),
        environment_multipliers={"production": 1.4, "staging": 1.1, "development": 0.7},
    ),
    # 3. Cross-account role assumption chain
    AttackPatternTemplate(
        pattern_id="CROSS_ACCOUNT_ASSUME",
        name="Cross-Account Role Assumption Chain",
        category=AttackPatternCategory.LATERAL_MOVEMENT,
        description=(
            "Agent can assume a role in another AWS account, potentially pivoting "
            "to accounts with weaker controls or higher-value targets."
        ),
        required_permissions=["sts:AssumeRole"],
        steps_template=[
            {"action": "sts:AssumeRole", "target_type": "role", "desc": "Assume role in target account"},
            {"action": "enumerate_resources", "target_type": "account", "desc": "Discover resources in target account"},
            {"action": "access_resources", "target_type": "any", "desc": "Access resources in target account"},
        ],
        mitre_technique_ids=[MitreTechnique.VALID_ACCOUNTS, MitreTechnique.LATERAL_MOVEMENT_REMOTE_SERVICES],
        base_likelihood=0.6,
        base_impact=0.85,
        base_exploitability=0.7,
        remediation=(
            "Restrict sts:AssumeRole with resource conditions limiting target role ARNs. "
            "Use external ID requirements for cross-account trust."
        ),
        environment_multipliers={"production": 1.5, "staging": 1.0, "development": 0.6},
    ),
    # 4. Bedrock agent data exfiltration
    AttackPatternTemplate(
        pattern_id="BEDROCK_DATA_EXFIL",
        name="Bedrock Agent Tool Invocation Data Exfiltration",
        category=AttackPatternCategory.DATA_EXFILTRATION,
        description=(
            "Bedrock agent's tool invocation permissions allow reading sensitive data "
            "stores and potentially exfiltrating data through model responses."
        ),
        required_permissions=["bedrock:InvokeModel", "bedrock:InvokeAgent"],
        steps_template=[
            {"action": "bedrock:InvokeAgent", "target_type": "agent", "desc": "Invoke Bedrock agent"},
            {"action": "tool_invocation", "target_type": "tool", "desc": "Agent invokes data-access tool"},
            {"action": "read_sensitive_data", "target_type": "data_store", "desc": "Tool reads sensitive data"},
            {"action": "exfiltrate_via_response", "target_type": "external", "desc": "Data returned in response"},
        ],
        mitre_technique_ids=[MitreTechnique.DATA_FROM_CLOUD_STORAGE, MitreTechnique.STEAL_APPLICATION_ACCESS_TOKEN],
        base_likelihood=0.65,
        base_impact=0.8,
        base_exploitability=0.75,
        remediation=(
            "Implement guardrails on Bedrock agent responses. Restrict tool invocation "
            "to specific data sources. Enable output filtering for sensitive data patterns."
        ),
        environment_multipliers={"production": 1.6, "staging": 1.1, "development": 0.5},
    ),
    # 5. SageMaker credential extraction
    AttackPatternTemplate(
        pattern_id="SAGEMAKER_CRED_EXTRACT",
        name="SageMaker Notebook IAM Credential Extraction",
        category=AttackPatternCategory.CREDENTIAL_THEFT,
        description=(
            "Access to a SageMaker notebook instance allows extraction of IAM credentials "
            "from the instance metadata service, enabling further lateral movement."
        ),
        required_permissions=["sagemaker:CreatePresignedNotebookInstanceUrl", "sagemaker:CreateNotebookInstance"],
        steps_template=[
            {"action": "sagemaker:CreatePresignedNotebookInstanceUrl", "target_type": "notebook", "desc": "Access notebook"},
            {"action": "execute_code", "target_type": "notebook", "desc": "Execute code in notebook"},
            {"action": "query_metadata_service", "target_type": "imds", "desc": "Query IMDS for credentials"},
            {"action": "use_credentials", "target_type": "role", "desc": "Use extracted credentials"},
        ],
        mitre_technique_ids=[MitreTechnique.UNSECURED_CREDENTIALS, MitreTechnique.STEAL_APPLICATION_ACCESS_TOKEN],
        base_likelihood=0.7,
        base_impact=0.75,
        base_exploitability=0.8,
        remediation=(
            "Restrict SageMaker notebook access. Use IMDSv2 with hop limit of 1. "
            "Apply least-privilege execution roles to notebook instances."
        ),
        environment_multipliers={"production": 1.3, "staging": 1.0, "development": 0.7},
    ),
    # 6. Secrets Manager credential theft
    AttackPatternTemplate(
        pattern_id="SECRETS_MANAGER_THEFT",
        name="Secrets Manager Credential Theft and Lateral Movement",
        category=AttackPatternCategory.CREDENTIAL_THEFT,
        description=(
            "Agent can read secrets from AWS Secrets Manager, extract credentials, "
            "and use them for lateral movement to other services or accounts."
        ),
        required_permissions=["secretsmanager:GetSecretValue"],
        steps_template=[
            {"action": "secretsmanager:ListSecrets", "target_type": "secrets_manager", "desc": "Enumerate secrets"},
            {"action": "secretsmanager:GetSecretValue", "target_type": "secret", "desc": "Extract secret value"},
            {"action": "authenticate", "target_type": "service", "desc": "Use credentials to authenticate"},
            {"action": "lateral_movement", "target_type": "any", "desc": "Move laterally with stolen credentials"},
        ],
        mitre_technique_ids=[MitreTechnique.CREDENTIALS_FROM_PASSWORD_STORES, MitreTechnique.LATERAL_MOVEMENT_REMOTE_SERVICES],
        base_likelihood=0.75,
        base_impact=0.85,
        base_exploitability=0.9,
        remediation=(
            "Restrict secretsmanager:GetSecretValue to specific secret ARNs. "
            "Enable secret rotation. Use resource policies on secrets. "
            "Monitor CloudTrail for secret access patterns."
        ),
        environment_multipliers={"production": 1.5, "staging": 1.2, "development": 0.6},
    ),
    # 7. S3 state file credential extraction
    AttackPatternTemplate(
        pattern_id="S3_STATE_FILE_CREDS",
        name="S3 Terraform State File Credential Extraction",
        category=AttackPatternCategory.CREDENTIAL_THEFT,
        description=(
            "Agent can read S3 buckets containing Terraform state files, which often "
            "contain plaintext credentials, API keys, and infrastructure secrets."
        ),
        required_permissions=["s3:GetObject"],
        steps_template=[
            {"action": "s3:ListBucket", "target_type": "s3_bucket", "desc": "List objects in state bucket"},
            {"action": "s3:GetObject", "target_type": "s3_object", "desc": "Download state file"},
            {"action": "extract_credentials", "target_type": "state_file", "desc": "Parse credentials from state"},
            {"action": "use_credentials", "target_type": "any", "desc": "Authenticate with extracted creds"},
        ],
        mitre_technique_ids=[MitreTechnique.UNSECURED_CREDENTIALS, MitreTechnique.DATA_FROM_CLOUD_STORAGE],
        base_likelihood=0.6,
        base_impact=0.9,
        base_exploitability=0.7,
        remediation=(
            "Encrypt state files with KMS. Restrict S3 bucket access with resource policies. "
            "Use state locking. Migrate to remote backends with access controls. "
            "Avoid storing secrets in Terraform state."
        ),
        environment_multipliers={"production": 1.6, "staging": 1.3, "development": 0.8},
    ),
    # 8. CloudFormation privilege escalation
    AttackPatternTemplate(
        pattern_id="CFN_PRIV_ESC",
        name="CloudFormation Stack Privilege Escalation",
        category=AttackPatternCategory.PRIVILEGE_ESCALATION,
        description=(
            "Agent can create or update CloudFormation stacks with a service role "
            "that has higher privileges, creating resources beyond the agent's own permissions."
        ),
        required_permissions=["cloudformation:CreateStack", "cloudformation:UpdateStack", "iam:PassRole"],
        steps_template=[
            {"action": "iam:PassRole", "target_type": "role", "desc": "Pass privileged role to CloudFormation"},
            {"action": "cloudformation:CreateStack", "target_type": "stack", "desc": "Create stack with elevated role"},
            {"action": "create_privileged_resources", "target_type": "any", "desc": "Stack creates privileged resources"},
            {"action": "access_created_resources", "target_type": "any", "desc": "Agent accesses new resources"},
        ],
        mitre_technique_ids=[MitreTechnique.ABUSE_ELEVATION_CONTROL, MitreTechnique.MODIFY_CLOUD_COMPUTE_INFRA],
        base_likelihood=0.65,
        base_impact=0.95,
        base_exploitability=0.75,
        remediation=(
            "Restrict cloudformation:CreateStack and UpdateStack. Limit iam:PassRole "
            "to specific CloudFormation service roles with minimal permissions. "
            "Use stack policies to prevent modification of critical resources."
        ),
        environment_multipliers={"production": 1.5, "staging": 1.2, "development": 0.7},
    ),
    # 9. Step Functions arbitrary execution
    AttackPatternTemplate(
        pattern_id="STEP_FUNCTIONS_EXEC",
        name="Step Functions State Machine Arbitrary Execution",
        category=AttackPatternCategory.ARBITRARY_EXECUTION,
        description=(
            "Agent can create or modify Step Functions state machines that execute "
            "arbitrary AWS API calls using the state machine's IAM role."
        ),
        required_permissions=["states:CreateStateMachine", "states:StartExecution"],
        steps_template=[
            {"action": "states:CreateStateMachine", "target_type": "state_machine", "desc": "Create state machine with privileged role"},
            {"action": "states:StartExecution", "target_type": "state_machine", "desc": "Start execution of state machine"},
            {"action": "execute_aws_sdk_action", "target_type": "any", "desc": "State machine executes arbitrary API calls"},
        ],
        mitre_technique_ids=[MitreTechnique.EXECUTION_SERVERLESS, MitreTechnique.ABUSE_ELEVATION_CONTROL],
        base_likelihood=0.55,
        base_impact=0.85,
        base_exploitability=0.7,
        remediation=(
            "Restrict states:CreateStateMachine and states:UpdateStateMachine. "
            "Ensure state machine IAM roles follow least privilege. "
            "Monitor state machine definitions for suspicious API call patterns."
        ),
        environment_multipliers={"production": 1.4, "staging": 1.1, "development": 0.6},
    ),
    # 10. ECS task metadata credential theft
    AttackPatternTemplate(
        pattern_id="ECS_METADATA_CREDS",
        name="ECS Task Metadata Service Credential Theft",
        category=AttackPatternCategory.CREDENTIAL_THEFT,
        description=(
            "Agent can run or access ECS tasks whose task role credentials are "
            "exposed via the task metadata endpoint, enabling credential extraction."
        ),
        required_permissions=["ecs:RunTask", "ecs:ExecuteCommand"],
        steps_template=[
            {"action": "ecs:RunTask", "target_type": "ecs_task", "desc": "Run ECS task with target role"},
            {"action": "ecs:ExecuteCommand", "target_type": "ecs_container", "desc": "Execute command in container"},
            {"action": "query_task_metadata", "target_type": "metadata_endpoint", "desc": "Query task metadata for credentials"},
            {"action": "use_task_credentials", "target_type": "role", "desc": "Use extracted task role credentials"},
        ],
        mitre_technique_ids=[MitreTechnique.UNSECURED_CREDENTIALS, MitreTechnique.STEAL_APPLICATION_ACCESS_TOKEN],
        base_likelihood=0.6,
        base_impact=0.8,
        base_exploitability=0.75,
        remediation=(
            "Restrict ecs:ExecuteCommand access. Use task role credential isolation. "
            "Apply least-privilege task roles. Enable ECS Exec logging. "
            "Use awsvpc networking mode with security groups."
        ),
        environment_multipliers={"production": 1.4, "staging": 1.1, "development": 0.6},
    ),
    # 11. SSM command execution pivot
    AttackPatternTemplate(
        pattern_id="SSM_COMMAND_PIVOT",
        name="SSM Command Execution EC2 Pivot",
        category=AttackPatternCategory.LATERAL_MOVEMENT,
        description=(
            "Agent can send SSM commands to EC2 instances, executing arbitrary "
            "commands and pivoting to the instance's IAM role and network position."
        ),
        required_permissions=["ssm:SendCommand", "ssm:StartSession"],
        steps_template=[
            {"action": "ssm:SendCommand", "target_type": "ec2_instance", "desc": "Send command to EC2 instance"},
            {"action": "execute_on_instance", "target_type": "ec2_instance", "desc": "Execute arbitrary commands"},
            {"action": "query_imds", "target_type": "imds", "desc": "Extract instance profile credentials"},
            {"action": "pivot_network", "target_type": "vpc", "desc": "Pivot to internal network resources"},
        ],
        mitre_technique_ids=[MitreTechnique.COMMAND_SCRIPTING_INTERPRETER, MitreTechnique.LATERAL_MOVEMENT_REMOTE_SERVICES],
        base_likelihood=0.7,
        base_impact=0.85,
        base_exploitability=0.8,
        remediation=(
            "Restrict ssm:SendCommand to specific instance IDs and document names. "
            "Use IMDSv2 on all EC2 instances. Enable SSM session logging. "
            "Apply tag-based access controls for SSM."
        ),
        environment_multipliers={"production": 1.5, "staging": 1.2, "development": 0.7},
    ),
    # 12. PassRole to Lambda creation
    AttackPatternTemplate(
        pattern_id="PASSROLE_LAMBDA_CREATE",
        name="PassRole with Lambda Function Creation",
        category=AttackPatternCategory.PRIVILEGE_ESCALATION,
        description=(
            "Agent can create a new Lambda function with a privileged execution role, "
            "then invoke it to perform actions beyond the agent's own permissions."
        ),
        required_permissions=["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        steps_template=[
            {"action": "lambda:CreateFunction", "target_type": "lambda", "desc": "Create Lambda with elevated role"},
            {"action": "iam:PassRole", "target_type": "role", "desc": "Attach privileged execution role"},
            {"action": "lambda:InvokeFunction", "target_type": "lambda", "desc": "Invoke new Lambda function"},
            {"action": "privileged_action", "target_type": "any", "desc": "Lambda executes privileged operations"},
        ],
        mitre_technique_ids=[MitreTechnique.EXECUTION_SERVERLESS, MitreTechnique.ABUSE_ELEVATION_CONTROL],
        base_likelihood=0.75,
        base_impact=0.9,
        base_exploitability=0.85,
        remediation=(
            "Restrict iam:PassRole to specific Lambda execution roles. "
            "Limit lambda:CreateFunction with condition keys. "
            "Audit existing Lambda execution roles for excess permissions."
        ),
        environment_multipliers={"production": 1.5, "staging": 1.2, "development": 0.7},
    ),
    # 13. Bedrock Knowledge Base data poisoning
    AttackPatternTemplate(
        pattern_id="BEDROCK_KB_POISON",
        name="Bedrock Knowledge Base Data Poisoning",
        category=AttackPatternCategory.DATA_EXFILTRATION,
        description=(
            "Agent can modify data sources backing a Bedrock Knowledge Base, "
            "poisoning the RAG pipeline to exfiltrate data or inject malicious instructions."
        ),
        required_permissions=["bedrock:UpdateKnowledgeBase", "s3:PutObject"],
        steps_template=[
            {"action": "s3:PutObject", "target_type": "s3_bucket", "desc": "Upload poisoned document to KB source"},
            {"action": "bedrock:StartIngestionJob", "target_type": "knowledge_base", "desc": "Trigger KB re-ingestion"},
            {"action": "bedrock:RetrieveAndGenerate", "target_type": "knowledge_base", "desc": "Query KB with poisoned data"},
            {"action": "exfiltrate_via_prompt", "target_type": "external", "desc": "Poisoned response exfiltrates data"},
        ],
        mitre_technique_ids=[MitreTechnique.DATA_FROM_CLOUD_STORAGE, MitreTechnique.IMPERSONATION],
        base_likelihood=0.5,
        base_impact=0.7,
        base_exploitability=0.6,
        remediation=(
            "Restrict write access to Knowledge Base data sources. "
            "Implement document validation before ingestion. "
            "Monitor for unexpected data source changes."
        ),
        environment_multipliers={"production": 1.4, "staging": 1.0, "development": 0.5},
    ),
    # 14. DynamoDB data exfiltration via scan
    AttackPatternTemplate(
        pattern_id="DYNAMODB_SCAN_EXFIL",
        name="DynamoDB Full Table Scan Data Exfiltration",
        category=AttackPatternCategory.DATA_EXFILTRATION,
        description=(
            "Agent has unrestricted DynamoDB Scan permissions allowing bulk extraction "
            "of sensitive data from tables containing PII, credentials, or business data."
        ),
        required_permissions=["dynamodb:Scan", "dynamodb:GetItem"],
        steps_template=[
            {"action": "dynamodb:ListTables", "target_type": "dynamodb", "desc": "Enumerate DynamoDB tables"},
            {"action": "dynamodb:DescribeTable", "target_type": "dynamodb_table", "desc": "Identify sensitive tables"},
            {"action": "dynamodb:Scan", "target_type": "dynamodb_table", "desc": "Full table scan for data extraction"},
            {"action": "exfiltrate_data", "target_type": "external", "desc": "Extract sensitive data"},
        ],
        mitre_technique_ids=[MitreTechnique.DATA_FROM_CLOUD_STORAGE, MitreTechnique.CLOUD_INFRASTRUCTURE_DISCOVERY],
        base_likelihood=0.7,
        base_impact=0.75,
        base_exploitability=0.85,
        remediation=(
            "Restrict dynamodb:Scan to specific tables. Use IAM condition keys to "
            "limit access to specific attributes. Prefer GetItem/Query over Scan. "
            "Enable DynamoDB table encryption and access logging."
        ),
        environment_multipliers={"production": 1.5, "staging": 1.1, "development": 0.6},
    ),
    # 15. EC2 instance profile credential abuse
    AttackPatternTemplate(
        pattern_id="EC2_INSTANCE_PROFILE_ABUSE",
        name="EC2 Instance Profile Attachment for Credential Access",
        category=AttackPatternCategory.PRIVILEGE_ESCALATION,
        description=(
            "Agent can associate or replace instance profiles on EC2 instances, "
            "attaching higher-privilege roles and then accessing those credentials "
            "via the instance metadata service."
        ),
        required_permissions=["ec2:AssociateIamInstanceProfile", "iam:PassRole"],
        steps_template=[
            {"action": "ec2:DescribeInstances", "target_type": "ec2_instance", "desc": "Identify target EC2 instances"},
            {"action": "iam:PassRole", "target_type": "role", "desc": "Pass privileged role to instance profile"},
            {"action": "ec2:AssociateIamInstanceProfile", "target_type": "ec2_instance", "desc": "Attach profile to instance"},
            {"action": "ssm:SendCommand", "target_type": "ec2_instance", "desc": "Access instance and extract credentials"},
        ],
        mitre_technique_ids=[MitreTechnique.ABUSE_ELEVATION_CONTROL, MitreTechnique.UNSECURED_CREDENTIALS],
        base_likelihood=0.55,
        base_impact=0.9,
        base_exploitability=0.65,
        remediation=(
            "Restrict ec2:AssociateIamInstanceProfile to specific instances. "
            "Limit iam:PassRole to non-admin roles. Use SCPs to prevent "
            "instance profile changes in production. Enable IMDSv2."
        ),
        environment_multipliers={"production": 1.6, "staging": 1.2, "development": 0.7},
    ),
    # 16. Glue job privilege escalation
    AttackPatternTemplate(
        pattern_id="GLUE_JOB_PRIV_ESC",
        name="Glue Job Privilege Escalation",
        category=AttackPatternCategory.PRIVILEGE_ESCALATION,
        description=(
            "Agent can create or modify AWS Glue jobs that run with a service role "
            "having higher privileges, enabling execution of arbitrary code "
            "with elevated permissions."
        ),
        required_permissions=["glue:CreateJob", "glue:StartJobRun", "iam:PassRole"],
        steps_template=[
            {"action": "glue:CreateJob", "target_type": "glue_job", "desc": "Create Glue job with privileged role"},
            {"action": "iam:PassRole", "target_type": "role", "desc": "Pass elevated role to Glue job"},
            {"action": "glue:StartJobRun", "target_type": "glue_job", "desc": "Start job execution"},
            {"action": "privileged_action", "target_type": "any", "desc": "Job executes privileged operations"},
        ],
        mitre_technique_ids=[MitreTechnique.ABUSE_ELEVATION_CONTROL, MitreTechnique.EXPLOITATION_FOR_PRIVILEGE_ESCALATION],
        base_likelihood=0.6,
        base_impact=0.85,
        base_exploitability=0.7,
        remediation=(
            "Restrict glue:CreateJob and glue:UpdateJob. Limit iam:PassRole "
            "to specific Glue service roles. Monitor Glue job definitions for changes."
        ),
        environment_multipliers={"production": 1.4, "staging": 1.1, "development": 0.6},
    ),
    # 17. CodeBuild project privilege escalation
    AttackPatternTemplate(
        pattern_id="CODEBUILD_PRIV_ESC",
        name="CodeBuild Project Privilege Escalation",
        category=AttackPatternCategory.PRIVILEGE_ESCALATION,
        description=(
            "Agent can create or modify CodeBuild projects with elevated service roles, "
            "executing arbitrary build commands with those elevated permissions."
        ),
        required_permissions=["codebuild:CreateProject", "codebuild:StartBuild", "iam:PassRole"],
        steps_template=[
            {"action": "codebuild:CreateProject", "target_type": "codebuild_project", "desc": "Create project with elevated role"},
            {"action": "iam:PassRole", "target_type": "role", "desc": "Pass privileged service role"},
            {"action": "codebuild:StartBuild", "target_type": "codebuild_project", "desc": "Start build execution"},
            {"action": "execute_buildspec", "target_type": "any", "desc": "Build executes arbitrary commands with elevated role"},
        ],
        mitre_technique_ids=[MitreTechnique.ABUSE_ELEVATION_CONTROL, MitreTechnique.COMMAND_SCRIPTING_INTERPRETER],
        base_likelihood=0.6,
        base_impact=0.85,
        base_exploitability=0.7,
        remediation=(
            "Restrict codebuild:CreateProject and codebuild:UpdateProject. "
            "Limit iam:PassRole to specific CodeBuild service roles. "
            "Audit buildspec.yml for suspicious commands."
        ),
        environment_multipliers={"production": 1.4, "staging": 1.1, "development": 0.6},
    ),
    # 18. KMS key compromise for data decryption
    AttackPatternTemplate(
        pattern_id="KMS_KEY_COMPROMISE",
        name="KMS Key Access for Data Decryption",
        category=AttackPatternCategory.DATA_EXFILTRATION,
        description=(
            "Agent has access to KMS keys used to encrypt sensitive data, enabling "
            "decryption of S3 objects, EBS volumes, or database snapshots."
        ),
        required_permissions=["kms:Decrypt", "kms:GenerateDataKey"],
        steps_template=[
            {"action": "kms:ListKeys", "target_type": "kms", "desc": "Enumerate available KMS keys"},
            {"action": "kms:DescribeKey", "target_type": "kms_key", "desc": "Identify keys protecting sensitive data"},
            {"action": "kms:Decrypt", "target_type": "kms_key", "desc": "Decrypt protected data"},
            {"action": "access_decrypted_data", "target_type": "any", "desc": "Read decrypted sensitive content"},
        ],
        mitre_technique_ids=[MitreTechnique.UNSECURED_CREDENTIALS, MitreTechnique.DATA_FROM_CLOUD_STORAGE],
        base_likelihood=0.5,
        base_impact=0.8,
        base_exploitability=0.6,
        remediation=(
            "Restrict kms:Decrypt to specific key ARNs. Use KMS key policies "
            "with condition keys. Separate encryption keys by data classification. "
            "Monitor CloudTrail for unexpected Decrypt calls."
        ),
        environment_multipliers={"production": 1.5, "staging": 1.2, "development": 0.7},
    ),
    # 19. EventBridge rule for persistence
    AttackPatternTemplate(
        pattern_id="EVENTBRIDGE_PERSISTENCE",
        name="EventBridge Rule Persistence Mechanism",
        category=AttackPatternCategory.PERSISTENCE,
        description=(
            "Agent can create EventBridge rules that trigger on specific events, "
            "maintaining persistent execution capability even after initial access is revoked."
        ),
        required_permissions=["events:PutRule", "events:PutTargets"],
        steps_template=[
            {"action": "events:PutRule", "target_type": "eventbridge_rule", "desc": "Create event rule for persistence"},
            {"action": "events:PutTargets", "target_type": "eventbridge_target", "desc": "Configure Lambda/SNS target"},
            {"action": "triggered_execution", "target_type": "lambda", "desc": "Rule triggers on future events"},
            {"action": "maintain_access", "target_type": "any", "desc": "Persistent access maintained"},
        ],
        mitre_technique_ids=[MitreTechnique.EXECUTION_SERVERLESS, MitreTechnique.MODIFY_CLOUD_COMPUTE_INFRA],
        base_likelihood=0.5,
        base_impact=0.7,
        base_exploitability=0.65,
        remediation=(
            "Restrict events:PutRule and events:PutTargets. Monitor for new "
            "EventBridge rules. Use AWS Config rules to detect unauthorized rules. "
            "Apply tag-based access controls."
        ),
        environment_multipliers={"production": 1.3, "staging": 1.0, "development": 0.5},
    ),
]


# ---------------------------------------------------------------------------
# Attack Graph
# ---------------------------------------------------------------------------


class AttackGraph:
    """A directed graph representing possible attack transitions between AWS resources.

    The graph models principals, resources, and the actions that connect them,
    enabling path discovery through BFS/DFS traversal.

    Attributes:
        nodes: Dictionary mapping node IDs to GraphNode instances.
        adjacency: Adjacency list mapping node IDs to lists of outgoing edges.
    """

    def __init__(self) -> None:
        """Initialize an empty attack graph."""
        self.nodes: dict[str, GraphNode] = {}
        self.adjacency: dict[str, list[GraphEdge]] = defaultdict(list)

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the attack graph.

        Args:
            node: The GraphNode to add.
        """
        self.nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a directed edge to the attack graph.

        Automatically adds source and target nodes if not already present.

        Args:
            edge: The GraphEdge to add.
        """
        if edge.source.node_id not in self.nodes:
            self.add_node(edge.source)
        if edge.target.node_id not in self.nodes:
            self.add_node(edge.target)
        self.adjacency[edge.source.node_id].append(edge)

    def get_neighbors(self, node_id: str) -> list[GraphEdge]:
        """Get all outgoing edges from a given node.

        Args:
            node_id: The ID of the node to query.

        Returns:
            List of GraphEdge instances representing outgoing transitions.
        """
        return self.adjacency.get(node_id, [])

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieve a node by its ID.

        Args:
            node_id: The ID of the node to retrieve.

        Returns:
            The GraphNode if found, None otherwise.
        """
        return self.nodes.get(node_id)

    @property
    def node_count(self) -> int:
        """Return the total number of nodes in the graph."""
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        """Return the total number of edges in the graph."""
        return sum(len(edges) for edges in self.adjacency.values())


# ---------------------------------------------------------------------------
# Attack Path Analyzer
# ---------------------------------------------------------------------------


class AttackPathAnalyzer:
    """Discovers and analyzes complete attack chains from AWS agent permissions.

    This analyzer builds an attack graph from an agent's effective permissions
    and known resource relationships, then uses graph traversal algorithms
    (BFS/DFS with cycle detection) to discover all reachable attack paths.

    Paths are ranked by likelihood, impact, and exploitability to prioritize
    remediation efforts.

    Example usage::

        analyzer = AttackPathAnalyzer()
        paths = analyzer.analyze_agent(agent)
        report = analyzer.generate_report(agent, paths)

    Attributes:
        graph: The attack graph built during analysis.
        patterns: Registry of known attack pattern templates.
        max_path_depth: Maximum allowed depth for path discovery.
        score_weights: Weights for computing combined score.
    """

    DEFAULT_MAX_PATH_DEPTH: int = 10
    DEFAULT_SCORE_WEIGHTS: dict[str, float] = {
        "likelihood": 0.3,
        "impact": 0.4,
        "exploitability": 0.3,
    }

    def __init__(
        self,
        patterns: Optional[list[AttackPatternTemplate]] = None,
        max_path_depth: int = DEFAULT_MAX_PATH_DEPTH,
        score_weights: Optional[dict[str, float]] = None,
    ) -> None:
        """Initialize the AttackPathAnalyzer.

        Args:
            patterns: Custom attack pattern templates. Defaults to KNOWN_ATTACK_PATTERNS.
            max_path_depth: Maximum depth for BFS/DFS path discovery.
            score_weights: Custom weights for combined score calculation.
        """
        self.graph = AttackGraph()
        self.patterns = patterns or KNOWN_ATTACK_PATTERNS
        self.max_path_depth = max_path_depth
        self.score_weights = score_weights or self.DEFAULT_SCORE_WEIGHTS
        self._discovered_paths: list[DiscoveredAttackPath] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_agent(
        self,
        agent: Agent,
        environment: Optional[Environment] = None,
    ) -> list[DiscoveredAttackPath]:
        """Perform full attack path analysis for a given agent.

        Builds the attack graph from the agent's permissions, discovers all
        reachable attack paths using graph traversal, matches against known
        patterns, and ranks results.

        Args:
            agent: The Agent to analyze.
            environment: The deployment environment for score adjustment.

        Returns:
            List of DiscoveredAttackPath instances, sorted by combined score descending.
        """
        self.graph = AttackGraph()
        self._discovered_paths = []

        # Build graph from agent permissions
        self._build_graph_from_agent(agent)

        # Discover paths using both pattern matching and graph traversal
        pattern_paths = self._match_patterns(agent, environment)
        graph_paths = self._discover_paths_bfs(agent)

        # Merge and deduplicate
        all_paths = self._merge_paths(pattern_paths, graph_paths)

        # Compute combined scores and assign severity
        for path in all_paths:
            path.combined_score = self._compute_combined_score(path)
            path.severity = self._score_to_severity(path.combined_score)

        # Sort by combined score descending
        all_paths.sort(key=lambda p: p.combined_score, reverse=True)
        self._discovered_paths = all_paths

        return all_paths

    def generate_report(
        self,
        agent: Agent,
        paths: Optional[list[DiscoveredAttackPath]] = None,
    ) -> PathReport:
        """Generate a comprehensive attack path report.

        Groups discovered paths by severity and category, produces
        prioritized recommendations, and creates an executive summary.

        Args:
            agent: The agent that was analyzed.
            paths: Pre-computed paths. If None, uses last analysis results.

        Returns:
            A PathReport containing all findings organized for consumption.
        """
        paths = paths or self._discovered_paths

        critical_paths = [p for p in paths if p.severity == Severity.CRITICAL]
        high_paths = [p for p in paths if p.severity == Severity.HIGH]
        medium_paths = [p for p in paths if p.severity == Severity.MEDIUM]
        low_paths = [p for p in paths if p.severity == Severity.LOW]

        # Group by category
        paths_by_category: dict[str, list[DiscoveredAttackPath]] = defaultdict(list)
        for path in paths:
            if path.pattern_match:
                # Find the pattern category
                for pattern in self.patterns:
                    if pattern.pattern_id == path.pattern_match:
                        paths_by_category[pattern.category.value].append(path)
                        break
            else:
                paths_by_category["uncategorized"].append(path)

        # Generate recommendations
        recommendations = self._generate_recommendations(paths)

        # Build summary
        summary = self._build_summary(agent, paths, critical_paths, high_paths)

        agent_id = getattr(agent, "agent_id", None) or getattr(agent, "name", "unknown")

        return PathReport(
            report_id=str(uuid.uuid4()),
            agent_id=str(agent_id),
            total_paths_discovered=len(paths),
            critical_paths=critical_paths,
            high_paths=high_paths,
            medium_paths=medium_paths,
            low_paths=low_paths,
            paths_by_category=dict(paths_by_category),
            top_recommendations=recommendations,
            summary=summary,
        )

    def discover_paths_from_node(
        self,
        start_node_id: str,
        target_node_type: Optional[str] = None,
    ) -> list[list[GraphEdge]]:
        """Discover all paths from a starting node using DFS with cycle detection.

        Args:
            start_node_id: The ID of the starting node.
            target_node_type: Optional filter for target node type at path terminus.

        Returns:
            List of paths, where each path is a list of GraphEdge instances.
        """
        paths: list[list[GraphEdge]] = []
        visited: set[str] = set()

        def _dfs(current_id: str, current_path: list[GraphEdge]) -> None:
            """Recursive DFS with cycle detection."""
            if len(current_path) >= self.max_path_depth:
                return

            visited.add(current_id)
            neighbors = self.graph.get_neighbors(current_id)

            for edge in neighbors:
                target_id = edge.target.node_id
                if target_id in visited:
                    continue  # Cycle detection

                new_path = current_path + [edge]

                # Check if this is a terminal path (no further edges or matches target type)
                target_neighbors = self.graph.get_neighbors(target_id)
                is_terminal = len(target_neighbors) == 0
                matches_target = (
                    target_node_type is None or edge.target.node_type == target_node_type
                )

                if is_terminal or (matches_target and len(new_path) > 1):
                    paths.append(new_path)

                # Continue DFS
                _dfs(target_id, new_path)

            visited.discard(current_id)

        _dfs(start_node_id, [])
        return paths

    def discover_paths_bfs(
        self,
        start_node_id: str,
        max_depth: Optional[int] = None,
    ) -> list[list[GraphEdge]]:
        """Discover all paths from a starting node using BFS with cycle detection.

        BFS ensures shortest paths are found first, useful for identifying
        minimum-step attack chains.

        Args:
            start_node_id: The ID of the starting node.
            max_depth: Maximum path depth. Defaults to self.max_path_depth.

        Returns:
            List of paths, where each path is a list of GraphEdge instances.
        """
        max_depth = max_depth or self.max_path_depth
        paths: list[list[GraphEdge]] = []

        # BFS queue entries: (current_node_id, path_so_far, visited_set)
        queue: deque[tuple[str, list[GraphEdge], frozenset[str]]] = deque()
        queue.append((start_node_id, [], frozenset([start_node_id])))

        while queue:
            current_id, current_path, visited = queue.popleft()

            if len(current_path) >= max_depth:
                continue

            neighbors = self.graph.get_neighbors(current_id)

            for edge in neighbors:
                target_id = edge.target.node_id
                if target_id in visited:
                    continue  # Cycle detection

                new_path = current_path + [edge]
                new_visited = visited | frozenset([target_id])

                # Record path if it has at least 2 steps
                if len(new_path) >= 2:
                    paths.append(new_path)

                # Continue BFS
                queue.append((target_id, new_path, new_visited))

        return paths

    def get_attack_patterns(self) -> list[AttackPatternTemplate]:
        """Return all registered attack pattern templates.

        Returns:
            List of AttackPatternTemplate instances.
        """
        return list(self.patterns)

    def add_pattern(self, pattern: AttackPatternTemplate) -> None:
        """Register a custom attack pattern template.

        Args:
            pattern: The AttackPatternTemplate to register.
        """
        self.patterns.append(pattern)

    # ------------------------------------------------------------------
    # Private: Graph Construction
    # ------------------------------------------------------------------

    def _build_graph_from_agent(self, agent: Agent) -> None:
        """Build the attack graph from an agent's effective permissions.

        Examines the agent's permissions and creates nodes/edges representing
        possible transitions between resources.

        Args:
            agent: The Agent whose permissions define the graph.
        """
        agent_id = getattr(agent, "agent_id", None) or getattr(agent, "name", "unknown")
        agent_node = GraphNode(
            node_id=str(agent_id),
            node_type="agent",
            properties={"agent": agent},
        )
        self.graph.add_node(agent_node)

        # Extract permissions from agent
        permissions = self._extract_permissions(agent)

        # Build edges based on permissions
        for permission in permissions:
            self._add_edges_for_permission(agent_node, permission)

    def _extract_permissions(self, agent: Agent) -> list[str]:
        """Extract effective permissions from an agent.

        Args:
            agent: The Agent to extract permissions from.

        Returns:
            List of IAM permission strings (e.g., 'iam:PassRole').
        """
        permissions: list[str] = []

        # Try common attribute patterns for permissions
        if hasattr(agent, "permissions"):
            perms = agent.permissions
            if isinstance(perms, list):
                permissions.extend(perms)
            elif isinstance(perms, dict):
                for actions in perms.values():
                    if isinstance(actions, list):
                        permissions.extend(actions)
        if hasattr(agent, "effective_permissions"):
            perms = agent.effective_permissions
            if isinstance(perms, list):
                permissions.extend(perms)
        # Handle identity_policies with PolicyDocument wrapper
        if hasattr(agent, "identity_policies") and agent.identity_policies:
            for policy_item in agent.identity_policies:
                if isinstance(policy_item, dict):
                    # Handle wrapped format: {"PolicyName": ..., "PolicyDocument": {...}}
                    if "PolicyDocument" in policy_item:
                        policy_doc = policy_item["PolicyDocument"]
                    else:
                        policy_doc = policy_item
                    statements = policy_doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        if stmt.get("Effect", "").upper() == "ALLOW":
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                permissions.append(actions)
                            elif isinstance(actions, list):
                                permissions.extend(actions)
        if hasattr(agent, "policies"):
            policies = agent.policies
            if isinstance(policies, list):
                for policy in policies:
                    if isinstance(policy, dict):
                        statements = policy.get("Statement", [])
                        for stmt in statements:
                            if stmt.get("Effect") == "Allow":
                                actions = stmt.get("Action", [])
                                if isinstance(actions, str):
                                    permissions.append(actions)
                                elif isinstance(actions, list):
                                    permissions.extend(actions)
        if hasattr(agent, "role_arn"):
            # Agent has an assumed role  -  add sts:AssumeRole implicitly
            permissions.append("sts:AssumeRole")

        return list(set(permissions))

    def _add_edges_for_permission(self, source_node: GraphNode, permission: str) -> None:
        """Add graph edges implied by a specific IAM permission.

        Maps known permissions to potential attack transitions in the graph.

        Args:
            source_node: The node possessing this permission.
            permission: The IAM permission string.
        """
        permission_lower = permission.lower()

        # Permission -> edge mapping
        edge_mappings: dict[str, list[tuple[str, str, str, float]]] = {
            "iam:passrole": [
                ("iam:PassRole", "role", "privileged_role", 0.9),
            ],
            "lambda:invokefunction": [
                ("lambda:InvokeFunction", "lambda", "lambda_function", 0.7),
            ],
            "lambda:createfunction": [
                ("lambda:CreateFunction", "lambda", "new_lambda", 0.8),
            ],
            "lambda:updatefunctioncode": [
                ("lambda:UpdateFunctionCode", "lambda", "lambda_function", 0.85),
            ],
            "sts:assumerole": [
                ("sts:AssumeRole", "role", "cross_account_role", 0.75),
            ],
            "secretsmanager:getsecretvalue": [
                ("secretsmanager:GetSecretValue", "secret", "sensitive_secret", 0.85),
            ],
            "s3:getobject": [
                ("s3:GetObject", "s3_object", "state_file_bucket", 0.6),
            ],
            "s3:putobject": [
                ("s3:PutObject", "s3_bucket", "data_bucket", 0.5),
            ],
            "cloudformation:createstack": [
                ("cloudformation:CreateStack", "cfn_stack", "new_stack", 0.7),
            ],
            "cloudformation:updatestack": [
                ("cloudformation:UpdateStack", "cfn_stack", "existing_stack", 0.7),
            ],
            "states:createstatemachine": [
                ("states:CreateStateMachine", "state_machine", "new_state_machine", 0.7),
            ],
            "states:startexecution": [
                ("states:StartExecution", "state_machine", "state_machine_exec", 0.65),
            ],
            "ecs:runtask": [
                ("ecs:RunTask", "ecs_task", "ecs_task_def", 0.7),
            ],
            "ecs:executecommand": [
                ("ecs:ExecuteCommand", "ecs_container", "ecs_container", 0.8),
            ],
            "ssm:sendcommand": [
                ("ssm:SendCommand", "ec2_instance", "managed_instance", 0.8),
            ],
            "ssm:startsession": [
                ("ssm:StartSession", "ec2_instance", "managed_instance", 0.75),
            ],
            "sagemaker:createpresignednotebookinstanceurl": [
                ("sagemaker:CreatePresignedNotebookInstanceUrl", "notebook", "sagemaker_notebook", 0.7),
            ],
            "bedrock:invokeagent": [
                ("bedrock:InvokeAgent", "agent", "bedrock_agent", 0.6),
            ],
            "bedrock:invokemodel": [
                ("bedrock:InvokeModel", "model", "bedrock_model", 0.5),
            ],
            "kms:decrypt": [
                ("kms:Decrypt", "kms_key", "encryption_key", 0.6),
            ],
            "dynamodb:scan": [
                ("dynamodb:Scan", "dynamodb_table", "sensitive_table", 0.7),
            ],
            "ec2:associateiaminstanceprofile": [
                ("ec2:AssociateIamInstanceProfile", "ec2_instance", "target_instance", 0.75),
            ],
            "glue:createjob": [
                ("glue:CreateJob", "glue_job", "new_glue_job", 0.7),
            ],
            "codebuild:createproject": [
                ("codebuild:CreateProject", "codebuild_project", "new_project", 0.7),
            ],
            "events:putrule": [
                ("events:PutRule", "eventbridge_rule", "persistence_rule", 0.5),
            ],
        }

        mappings = edge_mappings.get(permission_lower, [])
        for action, target_type, target_id, risk_weight in mappings:
            target_node = GraphNode(
                node_id=target_id,
                node_type=target_type,
                properties={"implied_by": permission},
            )
            edge = GraphEdge(
                source=source_node,
                target=target_node,
                action=action,
                permission_required=permission,
                conditions=[],
                risk_weight=risk_weight,
            )
            self.graph.add_edge(edge)

        # Add secondary edges for common escalation paths
        self._add_escalation_edges(source_node, permission_lower)

    def _add_escalation_edges(self, source_node: GraphNode, permission_lower: str) -> None:
        """Add secondary edges representing known escalation transitions.

        These edges represent what becomes possible after a primary action is taken.

        Args:
            source_node: The node originating the action.
            permission_lower: The lowercase permission string.
        """
        escalation_chains: dict[str, list[tuple[str, str, str, str, float]]] = {
            "iam:passrole": [
                ("privileged_role", "assume_via_service", "role", "service_assumed_role", 0.85),
                ("service_assumed_role", "admin_access", "any", "admin_target", 0.95),
            ],
            "lambda:updatefunctioncode": [
                ("lambda_function", "lambda:InvokeFunction", "lambda", "modified_lambda", 0.8),
                ("modified_lambda", "sts:AssumeRole", "role", "lambda_exec_role", 0.85),
            ],
            "ssm:sendcommand": [
                ("managed_instance", "query_imds", "imds", "instance_metadata", 0.8),
                ("instance_metadata", "use_credentials", "role", "instance_role_creds", 0.85),
            ],
            "ecs:executecommand": [
                ("ecs_container", "query_task_metadata", "metadata_endpoint", "task_metadata", 0.8),
                ("task_metadata", "use_task_credentials", "role", "task_role_creds", 0.85),
            ],
            "secretsmanager:getsecretvalue": [
                ("sensitive_secret", "authenticate", "service", "authenticated_service", 0.75),
                ("authenticated_service", "lateral_movement", "any", "lateral_target", 0.7),
            ],
            "s3:getobject": [
                ("state_file_bucket", "extract_credentials", "state_file", "extracted_creds", 0.7),
                ("extracted_creds", "use_credentials", "any", "cred_target", 0.75),
            ],
        }

        chains = escalation_chains.get(permission_lower, [])
        for src_id, action, target_type, target_id, risk_weight in chains:
            src_node = GraphNode(node_id=src_id, node_type="intermediate")
            tgt_node = GraphNode(node_id=target_id, node_type=target_type)
            edge = GraphEdge(
                source=src_node,
                target=tgt_node,
                action=action,
                permission_required=permission_lower,
                conditions=["Requires successful previous step"],
                risk_weight=risk_weight,
            )
            self.graph.add_edge(edge)

    # ------------------------------------------------------------------
    # Private: Pattern Matching
    # ------------------------------------------------------------------

    def _match_patterns(
        self,
        agent: Agent,
        environment: Optional[Environment] = None,
    ) -> list[DiscoveredAttackPath]:
        """Match known attack patterns against agent's effective permissions.

        Args:
            agent: The Agent to match patterns against.
            environment: Deployment environment for score adjustment.

        Returns:
            List of DiscoveredAttackPath instances from pattern matches.
        """
        agent_permissions = set(p.lower() for p in self._extract_permissions(agent))
        matched_paths: list[DiscoveredAttackPath] = []

        for pattern in self.patterns:
            required = set(p.lower() for p in pattern.required_permissions)

            # Check if agent has at least one required permission (partial match)
            # Full match = all required permissions present
            match_ratio = len(required & agent_permissions) / len(required) if required else 0.0

            if match_ratio >= 0.5:  # At least 50% of required permissions present
                path = self._pattern_to_path(pattern, agent, match_ratio, environment)
                matched_paths.append(path)

        return matched_paths

    def _pattern_to_path(
        self,
        pattern: AttackPatternTemplate,
        agent: Agent,
        match_ratio: float,
        environment: Optional[Environment] = None,
    ) -> DiscoveredAttackPath:
        """Convert a matched pattern template into a DiscoveredAttackPath.

        Args:
            pattern: The matched attack pattern template.
            agent: The agent being analyzed.
            match_ratio: Ratio of required permissions the agent possesses.
            environment: Deployment environment for score adjustment.

        Returns:
            A DiscoveredAttackPath representing the matched pattern.
        """
        agent_id = str(getattr(agent, "agent_id", None) or getattr(agent, "name", "unknown"))

        # Build steps from template
        steps: list[DiscoveredAttackStep] = []
        for i, step_tmpl in enumerate(pattern.steps_template, start=1):
            step = DiscoveredAttackStep(
                step_number=i,
                source_node=agent_id if i == 1 else pattern.steps_template[i - 2].get("target_type", "previous"),
                action=step_tmpl["action"],
                target_node=step_tmpl.get("target_type", "unknown"),
                permission_required=step_tmpl["action"],
                condition="Permission present" if match_ratio == 1.0 else "Partial permissions available",
                risk_contribution=pattern.base_impact / len(pattern.steps_template),
                description=step_tmpl.get("desc", ""),
            )
            steps.append(step)

        # Adjust scores based on match ratio and environment
        env_multiplier = 1.0
        if environment:
            env_name = environment.value if hasattr(environment, "value") else str(environment)
            env_multiplier = pattern.environment_multipliers.get(env_name, 1.0)

        likelihood = min(1.0, pattern.base_likelihood * match_ratio * env_multiplier)
        impact = min(1.0, pattern.base_impact * env_multiplier)
        exploitability = min(1.0, pattern.base_exploitability * match_ratio)

        # Determine target resource from last step
        target_resource = steps[-1].target_node if steps else "unknown"

        # Generate stable path ID
        path_id = self._generate_path_id(agent_id, pattern.pattern_id)

        return DiscoveredAttackPath(
            path_id=path_id,
            steps=steps,
            source_agent=agent_id,
            target_resource=target_resource,
            likelihood_score=likelihood,
            impact_score=impact,
            exploitability_score=exploitability,
            combined_score=0.0,  # Computed later
            description=pattern.description,
            mitre_technique_ids=pattern.mitre_technique_ids,
            remediation=pattern.remediation,
            pattern_match=pattern.pattern_id,
        )

    # ------------------------------------------------------------------
    # Private: Graph Traversal
    # ------------------------------------------------------------------

    def _discover_paths_bfs(self, agent: Agent) -> list[DiscoveredAttackPath]:
        """Discover attack paths from agent node using BFS.

        Args:
            agent: The agent to start discovery from.

        Returns:
            List of DiscoveredAttackPath instances found via graph traversal.
        """
        agent_id = str(getattr(agent, "agent_id", None) or getattr(agent, "name", "unknown"))

        if agent_id not in self.graph.nodes:
            return []

        raw_paths = self.discover_paths_bfs(agent_id)
        discovered: list[DiscoveredAttackPath] = []

        for raw_path in raw_paths:
            if len(raw_path) < 2:
                continue

            steps = self._edges_to_steps(raw_path)
            target_resource = raw_path[-1].target.node_id

            # Compute scores based on path characteristics
            likelihood = self._compute_path_likelihood(raw_path)
            impact = self._compute_path_impact(raw_path)
            exploitability = self._compute_path_exploitability(raw_path)

            path_id = self._generate_path_id(agent_id, target_resource)

            path = DiscoveredAttackPath(
                path_id=path_id,
                steps=steps,
                source_agent=agent_id,
                target_resource=target_resource,
                likelihood_score=likelihood,
                impact_score=impact,
                exploitability_score=exploitability,
                combined_score=0.0,  # Computed later
                description=f"Attack path from {agent_id} to {target_resource} via {len(steps)} steps",
                mitre_technique_ids=self._infer_mitre_techniques(raw_path),
                remediation=self._generate_path_remediation(raw_path),
            )
            discovered.append(path)

        return discovered

    def _edges_to_steps(self, edges: list[GraphEdge]) -> list[DiscoveredAttackStep]:
        """Convert a list of graph edges into DiscoveredAttackStep instances.

        Args:
            edges: Ordered list of graph edges forming a path.

        Returns:
            List of DiscoveredAttackStep instances.
        """
        steps: list[DiscoveredAttackStep] = []
        for i, edge in enumerate(edges, start=1):
            step = DiscoveredAttackStep(
                step_number=i,
                source_node=edge.source.node_id,
                action=edge.action,
                target_node=edge.target.node_id,
                permission_required=edge.permission_required,
                condition="; ".join(edge.conditions) if edge.conditions else "None",
                risk_contribution=edge.risk_weight,
                description=f"{edge.action} from {edge.source.node_id} to {edge.target.node_id}",
            )
            steps.append(step)
        return steps

    # ------------------------------------------------------------------
    # Private: Scoring
    # ------------------------------------------------------------------

    def _compute_path_likelihood(self, edges: list[GraphEdge]) -> float:
        """Compute likelihood score based on path characteristics.

        Shorter paths with fewer conditions are more likely to be exploited.

        Args:
            edges: The path edges.

        Returns:
            Likelihood score between 0.0 and 1.0.
        """
        if not edges:
            return 0.0

        # Base likelihood decreases with path length
        length_factor = max(0.2, 1.0 - (len(edges) - 1) * 0.15)

        # Conditions reduce likelihood
        total_conditions = sum(len(e.conditions) for e in edges)
        condition_factor = max(0.3, 1.0 - total_conditions * 0.1)

        return min(1.0, length_factor * condition_factor)

    def _compute_path_impact(self, edges: list[GraphEdge]) -> float:
        """Compute impact score based on what the path achieves.

        Higher impact for paths reaching sensitive resources.

        Args:
            edges: The path edges.

        Returns:
            Impact score between 0.0 and 1.0.
        """
        if not edges:
            return 0.0

        # Impact is determined by the terminal node type and accumulated risk
        terminal_node = edges[-1].target
        high_impact_types = {"role", "secret", "admin_target", "any", "kms_key"}
        medium_impact_types = {"lambda", "ec2_instance", "ecs_task", "state_machine"}

        base_impact = 0.5
        if terminal_node.node_type in high_impact_types:
            base_impact = 0.9
        elif terminal_node.node_type in medium_impact_types:
            base_impact = 0.7

        # Accumulate risk weights
        avg_risk = sum(e.risk_weight for e in edges) / len(edges)

        return min(1.0, base_impact * avg_risk * 1.2)

    def _compute_path_exploitability(self, edges: list[GraphEdge]) -> float:
        """Compute exploitability score based on ease of execution.

        Args:
            edges: The path edges.

        Returns:
            Exploitability score between 0.0 and 1.0.
        """
        if not edges:
            return 0.0

        # Average risk weight indicates how easy each step is
        avg_risk = sum(e.risk_weight for e in edges) / len(edges)

        # Fewer conditions = easier to exploit
        total_conditions = sum(len(e.conditions) for e in edges)
        condition_penalty = total_conditions * 0.05

        return min(1.0, max(0.1, avg_risk - condition_penalty))

    def _compute_combined_score(self, path: DiscoveredAttackPath) -> float:
        """Compute the weighted combined score for a path.

        Uses configurable weights for likelihood, impact, and exploitability.

        Args:
            path: The DiscoveredAttackPath to score.

        Returns:
            Combined score between 0.0 and 1.0.
        """
        score = (
            self.score_weights["likelihood"] * path.likelihood_score
            + self.score_weights["impact"] * path.impact_score
            + self.score_weights["exploitability"] * path.exploitability_score
        )
        return min(1.0, max(0.0, score))

    def _score_to_severity(self, score: float) -> Severity:
        """Map a combined score to a Severity level.

        Args:
            score: Combined score between 0.0 and 1.0.

        Returns:
            Appropriate Severity enum value.
        """
        if score >= 0.8:
            return Severity.CRITICAL
        elif score >= 0.6:
            return Severity.HIGH
        elif score >= 0.4:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    # ------------------------------------------------------------------
    # Private: MITRE Mapping
    # ------------------------------------------------------------------

    def _infer_mitre_techniques(self, edges: list[GraphEdge]) -> list[str]:
        """Infer MITRE ATT&CK technique IDs from path edges.

        Args:
            edges: The path edges.

        Returns:
            List of MITRE technique ID strings.
        """
        techniques: set[str] = set()
        action_to_mitre: dict[str, str] = {
            "iam:passrole": MitreTechnique.ABUSE_ELEVATION_CONTROL,
            "sts:assumerole": MitreTechnique.VALID_ACCOUNTS,
            "lambda:invokefunction": MitreTechnique.EXECUTION_SERVERLESS,
            "lambda:updatefunctioncode": MitreTechnique.EXECUTION_SERVERLESS,
            "secretsmanager:getsecretvalue": MitreTechnique.CREDENTIALS_FROM_PASSWORD_STORES,
            "s3:getobject": MitreTechnique.DATA_FROM_CLOUD_STORAGE,
            "ssm:sendcommand": MitreTechnique.COMMAND_SCRIPTING_INTERPRETER,
            "query_imds": MitreTechnique.UNSECURED_CREDENTIALS,
            "query_task_metadata": MitreTechnique.UNSECURED_CREDENTIALS,
            "lateral_movement": MitreTechnique.LATERAL_MOVEMENT_REMOTE_SERVICES,
            "use_credentials": MitreTechnique.ACCESS_TOKEN_MANIPULATION,
            "admin_access": MitreTechnique.ABUSE_ELEVATION_CONTROL,
        }

        for edge in edges:
            action_lower = edge.action.lower()
            if action_lower in action_to_mitre:
                techniques.add(action_to_mitre[action_lower])

        return list(techniques) if techniques else [MitreTechnique.VALID_ACCOUNTS]

    # ------------------------------------------------------------------
    # Private: Remediation Generation
    # ------------------------------------------------------------------

    def _generate_path_remediation(self, edges: list[GraphEdge]) -> str:
        """Generate remediation guidance for a discovered path.

        Args:
            edges: The path edges.

        Returns:
            Remediation string with actionable recommendations.
        """
        remediations: list[str] = []

        for edge in edges:
            action_lower = edge.action.lower()
            if "passrole" in action_lower:
                remediations.append("Restrict iam:PassRole with resource conditions")
            elif "lambda" in action_lower:
                remediations.append("Limit Lambda function permissions and execution roles")
            elif "assumerole" in action_lower:
                remediations.append("Add external ID and condition keys to role trust policies")
            elif "secretsmanager" in action_lower:
                remediations.append("Restrict secret access to specific ARNs")
            elif "s3" in action_lower:
                remediations.append("Apply bucket policies and encrypt sensitive objects")
            elif "ssm" in action_lower:
                remediations.append("Restrict SSM access to specific instances and documents")
            elif "ecs" in action_lower:
                remediations.append("Limit ECS task execution and command access")
            elif "imds" in action_lower or "metadata" in action_lower:
                remediations.append("Enforce IMDSv2 with hop limit of 1")

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_remediations: list[str] = []
        for r in remediations:
            if r not in seen:
                seen.add(r)
                unique_remediations.append(r)

        return "; ".join(unique_remediations) if unique_remediations else "Apply least-privilege permissions"

    # ------------------------------------------------------------------
    # Private: Report Helpers
    # ------------------------------------------------------------------

    def _generate_recommendations(self, paths: list[DiscoveredAttackPath]) -> list[str]:
        """Generate prioritized remediation recommendations from all paths.

        Args:
            paths: All discovered attack paths.

        Returns:
            List of prioritized recommendation strings.
        """
        if not paths:
            return ["No attack paths discovered  -  permissions appear well-scoped."]

        # Collect and deduplicate remediations, ordered by path severity
        recommendation_scores: dict[str, float] = {}
        for path in paths:
            remediation_parts = path.remediation.split("; ")
            for part in remediation_parts:
                part = part.strip()
                if part:
                    current_score = recommendation_scores.get(part, 0.0)
                    recommendation_scores[part] = max(current_score, path.combined_score)

        # Sort by score descending
        sorted_recommendations = sorted(
            recommendation_scores.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        return [rec for rec, _ in sorted_recommendations[:10]]

    def _build_summary(
        self,
        agent: Agent,
        all_paths: list[DiscoveredAttackPath],
        critical_paths: list[DiscoveredAttackPath],
        high_paths: list[DiscoveredAttackPath],
    ) -> str:
        """Build an executive summary for the path report.

        Args:
            agent: The agent analyzed.
            all_paths: All discovered paths.
            critical_paths: Paths with CRITICAL severity.
            high_paths: Paths with HIGH severity.

        Returns:
            Executive summary string.
        """
        agent_id = getattr(agent, "agent_id", None) or getattr(agent, "name", "unknown")
        total = len(all_paths)

        if total == 0:
            return (
                f"No attack paths discovered for agent '{agent_id}'. "
                f"The agent's permissions appear to be well-scoped with no "
                f"exploitable multi-step chains identified."
            )

        summary_parts = [
            f"Attack path analysis for agent '{agent_id}' discovered {total} potential attack chains.",
        ]

        if critical_paths:
            summary_parts.append(
                f"CRITICAL: {len(critical_paths)} path(s) with critical severity require "
                f"immediate remediation."
            )

        if high_paths:
            summary_parts.append(
                f"HIGH: {len(high_paths)} path(s) with high severity should be addressed promptly."
            )

        # Identify most dangerous pattern
        if all_paths:
            worst = all_paths[0]
            summary_parts.append(
                f"Highest risk: '{worst.description[:80]}...' "
                f"(combined score: {worst.combined_score:.2f})."
            )

        return " ".join(summary_parts)

    # ------------------------------------------------------------------
    # Private: Utility Methods
    # ------------------------------------------------------------------

    def _merge_paths(
        self,
        pattern_paths: list[DiscoveredAttackPath],
        graph_paths: list[DiscoveredAttackPath],
    ) -> list[DiscoveredAttackPath]:
        """Merge and deduplicate paths from pattern matching and graph discovery.

        Pattern-matched paths take priority over graph-discovered paths when
        they overlap (same source and target).

        Args:
            pattern_paths: Paths from pattern matching.
            graph_paths: Paths from graph traversal.

        Returns:
            Deduplicated list of all discovered paths.
        """
        seen_ids: set[str] = set()
        merged: list[DiscoveredAttackPath] = []

        # Pattern paths have priority
        for path in pattern_paths:
            if path.path_id not in seen_ids:
                seen_ids.add(path.path_id)
                merged.append(path)

        # Add unique graph paths
        for path in graph_paths:
            if path.path_id not in seen_ids:
                seen_ids.add(path.path_id)
                merged.append(path)

        return merged

    @staticmethod
    def _generate_path_id(source: str, target: str) -> str:
        """Generate a deterministic path ID from source and target.

        Args:
            source: Source node identifier.
            target: Target node identifier.

        Returns:
            A stable, unique path ID string.
        """
        content = f"{source}::{target}"
        hash_digest = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"path-{hash_digest}"


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


def analyze_agent_attack_paths(
    agent: Agent,
    environment: Optional[Environment] = None,
    max_depth: int = AttackPathAnalyzer.DEFAULT_MAX_PATH_DEPTH,
) -> list[DiscoveredAttackPath]:
    """Convenience function to analyze attack paths for an agent.

    Creates an analyzer, runs analysis, and returns discovered paths.

    Args:
        agent: The Agent to analyze.
        environment: Deployment environment for score adjustment.
        max_depth: Maximum path depth for discovery.

    Returns:
        List of DiscoveredAttackPath instances sorted by combined score.
    """
    analyzer = AttackPathAnalyzer(max_path_depth=max_depth)
    return analyzer.analyze_agent(agent, environment)


def generate_attack_path_report(
    agent: Agent,
    environment: Optional[Environment] = None,
) -> PathReport:
    """Convenience function to generate a full attack path report for an agent.

    Args:
        agent: The Agent to analyze.
        environment: Deployment environment for score adjustment.

    Returns:
        A PathReport containing all findings.
    """
    analyzer = AttackPathAnalyzer()
    paths = analyzer.analyze_agent(agent, environment)
    return analyzer.generate_report(agent, paths)


def get_known_patterns() -> list[AttackPatternTemplate]:
    """Return all known attack pattern templates.

    Returns:
        List of AttackPatternTemplate instances.
    """
    return list(KNOWN_ATTACK_PATTERNS)


def get_pattern_by_id(pattern_id: str) -> Optional[AttackPatternTemplate]:
    """Retrieve a specific attack pattern template by ID.

    Args:
        pattern_id: The unique pattern identifier.

    Returns:
        The AttackPatternTemplate if found, None otherwise.
    """
    for pattern in KNOWN_ATTACK_PATTERNS:
        if pattern.pattern_id == pattern_id:
            return pattern
    return None
