"""
aws_agent_identity_guard/attack_paths.py
────────────────────────────────────────────────────────────────────────────────
Attack-path analysis engine for AI agent identities.

Discovers and ranks potential attack chains available to an agent based on its
effective permissions. Identifies multi-step escalation paths including:

  • Role chaining — Agent -> AssumeRole -> Role B -> further privilege
  • PassRole exploitation — Agent -> PassRole -> Lambda/ECS -> escalated access
  • Data exfiltration — Agent -> S3/DynamoDB/Athena -> sensitive data
  • Credential theft — Agent -> SecretsManager/SSM/KMS -> harvested credentials
  • Lateral movement — Agent -> Lambda/SSM/ECS -> pivot to other services
  • Persistence — Agent -> CreateRole/CreateUser/EventBridge -> backdoor access
  • Confused deputy — Cross-service exploitation via misconfigured trust

Each path is scored with:
  • likelihood (0.0-1.0): probability of successful exploitation
  • impact (0.0-1.0): severity if the path is exploited
  • composite_score: likelihood * impact * 100

Paths are ranked by composite score (highest risk first).
"""

from __future__ import annotations

import logging
from typing import Any

from aws_agent_identity_guard.models import (
    AgentIdentity,
    AttackPath,
    AttackStep,
    EffectiveEffect,
    EffectivePermission,
)

logger = logging.getLogger(__name__)


class AttackPathAnalyzer:
    """
    Discovers and ranks attack paths available to an AI agent.

    Performs static analysis of effective permissions to identify multi-step
    attack chains that could lead to privilege escalation, data exfiltration,
    lateral movement, or persistent backdoor access.

    Usage:
        analyzer = AttackPathAnalyzer()
        paths = analyzer.analyze(agent, effective_permissions)
        for path in paths:
            print(analyzer.explain_path(path))
    """

    def __init__(self) -> None:
        """Initialize the attack path analyzer."""
        logger.info("AttackPathAnalyzer initialized")

    def analyze(
        self,
        agent: AgentIdentity,
        effective_permissions: list[EffectivePermission],
    ) -> list[AttackPath]:
        """
        Analyze all possible attack paths for an agent.

        Discovers paths across all categories (role chaining, PassRole exploitation,
        data exfiltration, credential theft, lateral movement, persistence, and
        confused deputy) and returns them ranked by composite risk score.

        Args:
            agent: The agent identity to analyze.
            effective_permissions: The agent's resolved effective permissions.

        Returns:
            List of AttackPath objects ranked by composite_score (highest first).

        Raises:
            ValueError: If agent or permissions are None.
        """
        if agent is None:
            raise ValueError("agent cannot be None")
        if effective_permissions is None:
            raise ValueError("effective_permissions cannot be None")

        logger.info(
            "Analyzing attack paths for agent '%s' (%s) with %d permissions",
            agent.name,
            agent.agent_id,
            len(effective_permissions),
        )

        # Filter to allowed permissions only
        allowed = self._filter_allowed(effective_permissions)
        if not allowed:
            logger.info("No allowed permissions — no attack paths possible")
            return []

        all_paths: list[AttackPath] = []

        try:
            # Discover paths in each category
            all_paths.extend(self._find_role_chaining_paths(allowed))
            all_paths.extend(self._find_passrole_paths(allowed))
            all_paths.extend(self._find_data_exfiltration_paths(allowed))
            all_paths.extend(self._find_credential_theft_paths(allowed))
            all_paths.extend(self._find_lateral_movement_paths(allowed))
            all_paths.extend(self._find_persistence_paths(allowed))
            all_paths.extend(self._find_confused_deputy_paths(allowed))

            # Rank by composite score
            ranked = self._rank_paths(all_paths)

            logger.info(
                "Discovered %d attack paths for agent '%s' (top score: %.1f)",
                len(ranked),
                agent.name,
                ranked[0].composite_score if ranked else 0.0,
            )

            return ranked

        except Exception as exc:
            logger.error(
                "Error analyzing attack paths for agent '%s': %s",
                agent.name,
                str(exc),
                exc_info=True,
            )
            raise

    # ─── Path Discovery Methods ───────────────────────────────────────────────

    def _find_role_chaining_paths(
        self, permissions: list[EffectivePermission]
    ) -> list[AttackPath]:
        """
        Find role-chaining attack paths (Agent -> AssumeRole -> Role B -> ...).

        Identifies paths where an agent can assume one or more roles, potentially
        chaining assumptions to reach higher-privilege roles.

        Args:
            permissions: Allowed effective permissions.

        Returns:
            List of attack paths involving role assumption chains.
        """
        paths: list[AttackPath] = []
        actions = self._extract_actions(permissions)

        assume_role_actions = {
            "sts:AssumeRole",
            "sts:AssumeRoleWithSAML",
            "sts:AssumeRoleWithWebIdentity",
        }

        matching_actions = actions & assume_role_actions
        if not matching_actions:
            return paths

        # Find the specific role resources that can be assumed
        assumable_roles = self._find_resources_for_actions(permissions, matching_actions)

        for action in matching_actions:
            for role_resource in assumable_roles:
                steps = [
                    AttackStep(
                        action=action,
                        resource=role_resource,
                        description=f"Assume role via {action}",
                        privilege_gained="Credentials for target role",
                    ),
                ]

                # If wildcard resource, this is critical (any role can be assumed)
                if role_resource == "*":
                    steps.append(
                        AttackStep(
                            action="sts:AssumeRole",
                            resource="arn:aws:iam::*:role/*",
                            description="Assume any role in any account (wildcard)",
                            privilege_gained="Full cross-account access",
                        ),
                    )
                    path = AttackPath(
                        steps=steps,
                        likelihood=0.9,
                        impact=1.0,
                        description=(
                            f"Agent -> {action} (wildcard) -> "
                            "Any role in any account -> Full privilege"
                        ),
                    )
                else:
                    # Specific role assumption
                    path = AttackPath(
                        steps=steps,
                        likelihood=0.7,
                        impact=0.7,
                        description=(
                            f"Agent -> {action} -> {self._short_arn(role_resource)} -> "
                            "Escalated credentials"
                        ),
                    )

                paths.append(path)

        logger.debug("Found %d role-chaining paths", len(paths))
        return paths

    def _find_passrole_paths(
        self, permissions: list[EffectivePermission]
    ) -> list[AttackPath]:
        """
        Find PassRole exploitation paths (Agent -> PassRole -> Service -> privilege).

        Identifies paths where an agent can pass a role to a compute service
        (Lambda, ECS, EC2, SageMaker, etc.) and then execute code with that
        role's elevated privileges.

        Args:
            permissions: Allowed effective permissions.

        Returns:
            List of attack paths involving PassRole exploitation.
        """
        paths: list[AttackPath] = []
        actions = self._extract_actions(permissions)

        if "iam:PassRole" not in actions:
            return paths

        passrole_resources = self._find_resources_for_actions(
            permissions, {"iam:PassRole"}
        )

        # Services that can receive a passed role
        compute_services = {
            "lambda:CreateFunction": (
                "Lambda function",
                "Execute arbitrary code as the passed role",
                0.85,
                0.9,
            ),
            "lambda:UpdateFunctionConfiguration": (
                "Lambda function",
                "Modify function to use a higher-privilege role",
                0.75,
                0.85,
            ),
            "ec2:RunInstances": (
                "EC2 instance",
                "Launch instance with instance profile for escalated access",
                0.7,
                0.85,
            ),
            "ecs:RunTask": (
                "ECS task",
                "Run container with task role for escalated access",
                0.75,
                0.85,
            ),
            "ecs:CreateService": (
                "ECS service",
                "Create service running with escalated task role",
                0.7,
                0.8,
            ),
            "sagemaker:CreateNotebookInstance": (
                "SageMaker notebook",
                "Interactive environment with escalated role",
                0.7,
                0.85,
            ),
            "sagemaker:CreateTrainingJob": (
                "SageMaker training job",
                "Execute training code with escalated role",
                0.65,
                0.8,
            ),
            "cloudformation:CreateStack": (
                "CloudFormation stack",
                "Deploy arbitrary resources with escalated role",
                0.8,
                0.95,
            ),
            "glue:CreateDevEndpoint": (
                "Glue dev endpoint",
                "Interactive development environment with escalated role",
                0.7,
                0.8,
            ),
            "datapipeline:CreatePipeline": (
                "Data Pipeline",
                "Execute pipeline activities with escalated role",
                0.6,
                0.75,
            ),
            "bedrock:CreateAgent": (
                "Bedrock agent",
                "AI agent executing with escalated role privileges",
                0.75,
                0.9,
            ),
        }

        for service_action, (service_name, description, likelihood, impact) in compute_services.items():
            if service_action in actions:
                for role_resource in passrole_resources:
                    steps = [
                        AttackStep(
                            action="iam:PassRole",
                            resource=role_resource,
                            description=f"Pass high-privilege role to {service_name}",
                            privilege_gained=f"Role assigned to {service_name}",
                        ),
                        AttackStep(
                            action=service_action,
                            resource="*",
                            description=f"Create/launch {service_name} with passed role",
                            privilege_gained=description,
                        ),
                    ]

                    # Wildcard PassRole is more dangerous
                    effective_likelihood = likelihood + 0.1 if role_resource == "*" else likelihood

                    path = AttackPath(
                        steps=steps,
                        likelihood=min(1.0, effective_likelihood),
                        impact=impact,
                        description=(
                            f"Agent -> iam:PassRole ({self._short_arn(role_resource)}) -> "
                            f"{service_action} -> {description}"
                        ),
                    )
                    paths.append(path)

        logger.debug("Found %d PassRole paths", len(paths))
        return paths

    def _find_data_exfiltration_paths(
        self, permissions: list[EffectivePermission]
    ) -> list[AttackPath]:
        """
        Find data exfiltration paths (Agent -> S3/DynamoDB/Athena -> sensitive data).

        Identifies paths where an agent can access, copy, or extract large
        volumes of potentially sensitive data.

        Args:
            permissions: Allowed effective permissions.

        Returns:
            List of attack paths involving data exfiltration.
        """
        paths: list[AttackPath] = []
        actions = self._extract_actions(permissions)

        # S3 exfiltration
        s3_read_actions = {"s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"}
        s3_matches = actions & s3_read_actions
        if s3_matches:
            s3_resources = self._find_resources_for_actions(permissions, s3_matches)
            for resource in s3_resources:
                steps = [
                    AttackStep(
                        action="s3:ListBucket",
                        resource=resource,
                        description="Enumerate bucket contents",
                        privilege_gained="Knowledge of available objects",
                    ),
                    AttackStep(
                        action="s3:GetObject",
                        resource=resource,
                        description="Download objects from bucket",
                        privilege_gained="Access to stored data",
                    ),
                ]
                is_wildcard = resource == "*"
                path = AttackPath(
                    steps=steps,
                    likelihood=0.8 if is_wildcard else 0.6,
                    impact=0.8 if is_wildcard else 0.6,
                    description=(
                        f"Agent -> S3 access ({self._short_arn(resource)}) -> "
                        "Data exfiltration"
                    ),
                )
                paths.append(path)

        # DynamoDB exfiltration
        ddb_actions = {"dynamodb:Scan", "dynamodb:Query", "dynamodb:BatchGetItem"}
        ddb_matches = actions & ddb_actions
        if ddb_matches:
            ddb_resources = self._find_resources_for_actions(permissions, ddb_matches)
            for resource in ddb_resources:
                steps = [
                    AttackStep(
                        action="dynamodb:Scan",
                        resource=resource,
                        description="Full table scan to extract all records",
                        privilege_gained="Access to all table data",
                    ),
                ]
                path = AttackPath(
                    steps=steps,
                    likelihood=0.7,
                    impact=0.7,
                    description=(
                        f"Agent -> DynamoDB scan ({self._short_arn(resource)}) -> "
                        "Bulk data extraction"
                    ),
                )
                paths.append(path)

        # Athena/Glue exfiltration
        analytics_actions = {
            "athena:StartQueryExecution",
            "glue:GetTable",
            "glue:GetTables",
        }
        analytics_matches = actions & analytics_actions
        if analytics_matches:
            steps = [
                AttackStep(
                    action=next(iter(analytics_matches)),
                    resource="*",
                    description="Query data lake via analytics service",
                    privilege_gained="Access to data lake contents",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.6,
                impact=0.75,
                description="Agent -> Analytics service -> Data lake exfiltration",
            )
            paths.append(path)

        # CloudWatch Logs exfiltration (may contain secrets)
        log_actions = {"logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartQuery"}
        log_matches = actions & log_actions
        if log_matches:
            steps = [
                AttackStep(
                    action=next(iter(log_matches)),
                    resource="*",
                    description="Access CloudWatch logs (may contain secrets/tokens)",
                    privilege_gained="Credentials and sensitive data from logs",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.5,
                impact=0.6,
                description="Agent -> CloudWatch Logs -> Credential/data harvesting",
            )
            paths.append(path)

        logger.debug("Found %d data exfiltration paths", len(paths))
        return paths

    def _find_credential_theft_paths(
        self, permissions: list[EffectivePermission]
    ) -> list[AttackPath]:
        """
        Find credential theft paths (Agent -> SecretsManager/SSM/KMS -> credentials).

        Identifies paths where an agent can retrieve stored secrets, decrypt
        sensitive data, or access credential stores.

        Args:
            permissions: Allowed effective permissions.

        Returns:
            List of attack paths involving credential theft.
        """
        paths: list[AttackPath] = []
        actions = self._extract_actions(permissions)

        # Secrets Manager
        secrets_actions = {"secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"}
        secrets_matches = actions & secrets_actions
        if secrets_matches:
            resources = self._find_resources_for_actions(permissions, secrets_matches)
            for resource in resources:
                steps = []
                if "secretsmanager:ListSecrets" in actions:
                    steps.append(
                        AttackStep(
                            action="secretsmanager:ListSecrets",
                            resource=resource,
                            description="Enumerate available secrets",
                            privilege_gained="Knowledge of secret names and metadata",
                        )
                    )
                if "secretsmanager:GetSecretValue" in actions:
                    steps.append(
                        AttackStep(
                            action="secretsmanager:GetSecretValue",
                            resource=resource,
                            description="Retrieve secret value (API keys, passwords, tokens)",
                            privilege_gained="Plaintext credentials",
                        )
                    )

                if steps:
                    path = AttackPath(
                        steps=steps,
                        likelihood=0.85,
                        impact=0.9,
                        description=(
                            f"Agent -> SecretsManager ({self._short_arn(resource)}) -> "
                            "Credential theft"
                        ),
                    )
                    paths.append(path)

        # SSM Parameter Store
        ssm_actions = {"ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"}
        ssm_matches = actions & ssm_actions
        if ssm_matches:
            resources = self._find_resources_for_actions(permissions, ssm_matches)
            for resource in resources:
                steps = [
                    AttackStep(
                        action=next(iter(ssm_matches)),
                        resource=resource,
                        description="Retrieve SSM parameters (may include SecureString secrets)",
                        privilege_gained="Stored configuration and credentials",
                    ),
                ]
                path = AttackPath(
                    steps=steps,
                    likelihood=0.75,
                    impact=0.8,
                    description=(
                        f"Agent -> SSM Parameter Store ({self._short_arn(resource)}) -> "
                        "Secret retrieval"
                    ),
                )
                paths.append(path)

        # KMS decryption (can unlock encrypted data)
        kms_actions = {"kms:Decrypt", "kms:GenerateDataKey", "kms:CreateGrant"}
        kms_matches = actions & kms_actions
        if kms_matches:
            resources = self._find_resources_for_actions(permissions, kms_matches)
            for resource in resources:
                steps = [
                    AttackStep(
                        action=next(iter(kms_matches)),
                        resource=resource,
                        description="Use KMS key to decrypt protected data",
                        privilege_gained="Ability to decrypt encrypted secrets and data",
                    ),
                ]

                # CreateGrant is particularly dangerous (persistent key access)
                impact = 0.9 if "kms:CreateGrant" in kms_matches else 0.7
                path = AttackPath(
                    steps=steps,
                    likelihood=0.7,
                    impact=impact,
                    description=(
                        f"Agent -> KMS ({self._short_arn(resource)}) -> "
                        "Decrypt sensitive data"
                    ),
                )
                paths.append(path)

        # IAM Access Key creation (credential generation)
        if "iam:CreateAccessKey" in actions:
            steps = [
                AttackStep(
                    action="iam:CreateAccessKey",
                    resource="*",
                    description="Create new access keys for IAM users",
                    privilege_gained="Long-lived credentials for any user",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.8,
                impact=0.9,
                description="Agent -> iam:CreateAccessKey -> Credential generation",
            )
            paths.append(path)

        logger.debug("Found %d credential theft paths", len(paths))
        return paths

    def _find_lateral_movement_paths(
        self, permissions: list[EffectivePermission]
    ) -> list[AttackPath]:
        """
        Find lateral movement paths (Agent -> Lambda/SSM/ECS -> other services).

        Identifies paths where an agent can pivot to other compute environments,
        invoke functions, start sessions, or trigger workflows.

        Args:
            permissions: Allowed effective permissions.

        Returns:
            List of attack paths involving lateral movement.
        """
        paths: list[AttackPath] = []
        actions = self._extract_actions(permissions)

        # Lambda invocation (execute code in other functions)
        lambda_invoke_actions = {"lambda:InvokeFunction", "lambda:InvokeAsync"}
        lambda_matches = actions & lambda_invoke_actions
        if lambda_matches:
            resources = self._find_resources_for_actions(permissions, lambda_matches)
            for resource in resources:
                steps = [
                    AttackStep(
                        action=next(iter(lambda_matches)),
                        resource=resource,
                        description="Invoke Lambda function to execute in its role context",
                        privilege_gained="Execution context of target Lambda's role",
                    ),
                ]
                # Chain: if the lambda has S3/secrets access
                steps.append(
                    AttackStep(
                        action="(target Lambda's permissions)",
                        resource="*",
                        description="Lambda function accesses resources with its own role",
                        privilege_gained="Access to resources permitted by Lambda's role",
                    ),
                )
                path = AttackPath(
                    steps=steps,
                    likelihood=0.75,
                    impact=0.7,
                    description=(
                        f"Agent -> Lambda invoke ({self._short_arn(resource)}) -> "
                        "Pivot to Lambda's role permissions"
                    ),
                )
                paths.append(path)

        # SSM session (direct instance access)
        ssm_session_actions = {"ssm:StartSession", "ssm:SendCommand"}
        ssm_matches = actions & ssm_session_actions
        if ssm_matches:
            resources = self._find_resources_for_actions(permissions, ssm_matches)
            for resource in resources:
                steps = [
                    AttackStep(
                        action=next(iter(ssm_matches)),
                        resource=resource,
                        description="Start SSM session or send command to EC2 instance",
                        privilege_gained="Shell access to EC2 instance",
                    ),
                    AttackStep(
                        action="(instance role)",
                        resource="arn:aws:iam::*:role/EC2InstanceRole",
                        description="Access instance metadata for instance role credentials",
                        privilege_gained="Instance role temporary credentials",
                    ),
                ]
                path = AttackPath(
                    steps=steps,
                    likelihood=0.8,
                    impact=0.85,
                    description=(
                        f"Agent -> SSM ({self._short_arn(resource)}) -> "
                        "EC2 shell access -> Instance role credentials"
                    ),
                )
                paths.append(path)

        # ECS/EKS task execution
        container_actions = {"ecs:RunTask", "ecs:StartTask", "eks:CreatePod"}
        container_matches = actions & container_actions
        if container_matches:
            steps = [
                AttackStep(
                    action=next(iter(container_matches)),
                    resource="*",
                    description="Launch container in cluster environment",
                    privilege_gained="Execution context in shared infrastructure",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.65,
                impact=0.7,
                description="Agent -> Container service -> Pivot to cluster network/roles",
            )
            paths.append(path)

        # Step Functions (workflow orchestration)
        if "states:StartExecution" in actions or "stepfunctions:StartExecution" in actions:
            steps = [
                AttackStep(
                    action="states:StartExecution",
                    resource="*",
                    description="Start Step Functions execution",
                    privilege_gained="Orchestrate multi-service workflow",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.6,
                impact=0.65,
                description="Agent -> Step Functions -> Multi-service orchestration",
            )
            paths.append(path)

        # Bedrock agent invocation
        bedrock_actions = {"bedrock:InvokeAgent", "bedrock:InvokeModel"}
        bedrock_matches = actions & bedrock_actions
        if bedrock_matches:
            steps = [
                AttackStep(
                    action=next(iter(bedrock_matches)),
                    resource="*",
                    description="Invoke Bedrock agent/model with potential tool access",
                    privilege_gained="Execution in Bedrock agent's tool/role context",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.6,
                impact=0.7,
                description="Agent -> Bedrock invoke -> Pivot to Bedrock agent's permissions",
            )
            paths.append(path)

        logger.debug("Found %d lateral movement paths", len(paths))
        return paths

    def _find_persistence_paths(
        self, permissions: list[EffectivePermission]
    ) -> list[AttackPath]:
        """
        Find persistence paths (Agent -> CreateRole/CreateUser -> backdoor access).

        Identifies paths where an agent can establish persistent access that
        survives credential rotation, session expiry, or role assumption limits.

        Args:
            permissions: Allowed effective permissions.

        Returns:
            List of attack paths involving persistence establishment.
        """
        paths: list[AttackPath] = []
        actions = self._extract_actions(permissions)

        # Create new IAM user/role with admin access
        if "iam:CreateUser" in actions:
            steps = [
                AttackStep(
                    action="iam:CreateUser",
                    resource="*",
                    description="Create new IAM user",
                    privilege_gained="New IAM identity",
                ),
            ]
            if "iam:CreateAccessKey" in actions:
                steps.append(
                    AttackStep(
                        action="iam:CreateAccessKey",
                        resource="*",
                        description="Create access keys for new user",
                        privilege_gained="Long-lived credentials",
                    )
                )
            if "iam:AttachUserPolicy" in actions or "iam:PutUserPolicy" in actions:
                attach_action = (
                    "iam:AttachUserPolicy"
                    if "iam:AttachUserPolicy" in actions
                    else "iam:PutUserPolicy"
                )
                steps.append(
                    AttackStep(
                        action=attach_action,
                        resource="*",
                        description="Attach admin policy to new user",
                        privilege_gained="Administrative access via backdoor user",
                    )
                )
            path = AttackPath(
                steps=steps,
                likelihood=0.8,
                impact=0.95,
                description="Agent -> Create IAM user -> Attach admin policy -> Persistent backdoor",
            )
            paths.append(path)

        # Create new role with permissive trust
        if "iam:CreateRole" in actions:
            steps = [
                AttackStep(
                    action="iam:CreateRole",
                    resource="*",
                    description="Create new IAM role with attacker-controlled trust policy",
                    privilege_gained="New role assumable by attacker",
                ),
            ]
            if "iam:AttachRolePolicy" in actions:
                steps.append(
                    AttackStep(
                        action="iam:AttachRolePolicy",
                        resource="*",
                        description="Attach AdministratorAccess to new role",
                        privilege_gained="Administrative access via backdoor role",
                    )
                )
            path = AttackPath(
                steps=steps,
                likelihood=0.75,
                impact=0.9,
                description="Agent -> Create role with permissive trust -> Admin backdoor",
            )
            paths.append(path)

        # Modify existing role trust policy
        if "iam:UpdateAssumeRolePolicy" in actions:
            steps = [
                AttackStep(
                    action="iam:UpdateAssumeRolePolicy",
                    resource="*",
                    description="Modify role trust policy to allow attacker assumption",
                    privilege_gained="Ability to assume existing high-privilege roles",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.8,
                impact=0.9,
                description="Agent -> UpdateAssumeRolePolicy -> Hijack existing admin role",
            )
            paths.append(path)

        # Event-based persistence (CloudWatch Events + Lambda)
        event_actions = {"events:PutRule", "events:PutTargets"}
        if event_actions & actions:
            steps = [
                AttackStep(
                    action="events:PutRule",
                    resource="*",
                    description="Create scheduled rule for periodic execution",
                    privilege_gained="Persistent scheduled trigger",
                ),
                AttackStep(
                    action="events:PutTargets",
                    resource="*",
                    description="Point rule at Lambda/SNS for persistent callback",
                    privilege_gained="Scheduled backdoor execution",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.6,
                impact=0.7,
                description="Agent -> EventBridge rule -> Persistent scheduled backdoor",
            )
            paths.append(path)

        # Lambda-based persistence
        if "lambda:CreateFunction" in actions and "lambda:AddPermission" in actions:
            steps = [
                AttackStep(
                    action="lambda:CreateFunction",
                    resource="*",
                    description="Create Lambda function with backdoor code",
                    privilege_gained="Persistent code execution",
                ),
                AttackStep(
                    action="lambda:AddPermission",
                    resource="*",
                    description="Add resource-based policy for external invocation",
                    privilege_gained="Externally-triggerable backdoor",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.7,
                impact=0.8,
                description="Agent -> Lambda create + add permission -> Externally-invocable backdoor",
            )
            paths.append(path)

        logger.debug("Found %d persistence paths", len(paths))
        return paths

    def _find_confused_deputy_paths(
        self, permissions: list[EffectivePermission]
    ) -> list[AttackPath]:
        """
        Find confused-deputy attack paths (cross-service exploitation).

        Identifies paths where an agent can exploit service-to-service trust
        relationships to gain access beyond its direct permissions.

        Args:
            permissions: Allowed effective permissions.

        Returns:
            List of attack paths involving confused deputy exploitation.
        """
        paths: list[AttackPath] = []
        actions = self._extract_actions(permissions)

        # S3 bucket policy modification -> confused deputy via other services
        if "s3:PutBucketPolicy" in actions:
            steps = [
                AttackStep(
                    action="s3:PutBucketPolicy",
                    resource="*",
                    description="Modify bucket policy to allow access from another AWS service",
                    privilege_gained="Cross-service data access via bucket policy",
                ),
                AttackStep(
                    action="(service-linked access)",
                    resource="arn:aws:s3:::*/*",
                    description="Exploit service role's implicit bucket access",
                    privilege_gained="Data access via confused deputy",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.5,
                impact=0.7,
                description="Agent -> S3 bucket policy modification -> Confused deputy data access",
            )
            paths.append(path)

        # SNS/SQS cross-account subscription
        cross_service_actions = {
            "sns:Subscribe",
            "sns:SetTopicAttributes",
            "sqs:SetQueueAttributes",
            "sqs:AddPermission",
        }
        cross_matches = actions & cross_service_actions
        if cross_matches:
            steps = [
                AttackStep(
                    action=next(iter(cross_matches)),
                    resource="*",
                    description="Modify messaging service policy for cross-account access",
                    privilege_gained="Cross-account message interception",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.45,
                impact=0.6,
                description="Agent -> SNS/SQS policy modification -> Cross-account interception",
            )
            paths.append(path)

        # Lambda resource-based policy (allow external invocation)
        if "lambda:AddPermission" in actions:
            steps = [
                AttackStep(
                    action="lambda:AddPermission",
                    resource="*",
                    description="Add resource-based policy to Lambda allowing cross-account invoke",
                    privilege_gained="External access to Lambda execution",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.55,
                impact=0.7,
                description="Agent -> Lambda AddPermission -> Cross-account function invocation",
            )
            paths.append(path)

        # API Gateway manipulation
        apigw_actions = {
            "apigateway:UpdateRestApi",
            "apigateway:CreateDeployment",
            "apigateway:PutIntegration",
        }
        apigw_matches = actions & apigw_actions
        if apigw_matches:
            steps = [
                AttackStep(
                    action=next(iter(apigw_matches)),
                    resource="*",
                    description="Modify API Gateway to route traffic to attacker endpoint",
                    privilege_gained="Request interception and data exfiltration",
                ),
            ]
            path = AttackPath(
                steps=steps,
                likelihood=0.4,
                impact=0.75,
                description="Agent -> API Gateway modification -> Traffic interception",
            )
            paths.append(path)

        logger.debug("Found %d confused deputy paths", len(paths))
        return paths

    # ─── Ranking and Explanation ──────────────────────────────────────────────

    def _rank_paths(self, paths: list[AttackPath]) -> list[AttackPath]:
        """
        Rank attack paths by composite score (likelihood * impact * 100).

        Ensures composite_score is correctly computed and sorts paths
        from highest risk (most dangerous) to lowest.

        Args:
            paths: Unranked list of attack paths.

        Returns:
            Sorted list of attack paths (highest composite_score first).
        """
        # Ensure composite scores are computed
        for path in paths:
            if path.composite_score == 0.0 and path.steps:
                path.composite_score = round(path.likelihood * path.impact * 100, 2)

        return sorted(paths, key=lambda p: p.composite_score, reverse=True)

    def explain_path(self, path: AttackPath) -> str:
        """
        Generate a human-readable explanation of an attack path.

        Produces a formatted chain showing each step with arrows, including
        the action, resource, and privilege gained at each stage.

        Args:
            path: The attack path to explain.

        Returns:
            Formatted string explanation of the attack chain.

        Example:
            "Agent -> iam:PassRole (arn:...:role/Admin) -> lambda:CreateFunction (*) ->
             Execute arbitrary code as Admin role [Likelihood: 0.85, Impact: 0.90,
             Score: 76.50]"
        """
        if not path.steps:
            return "Empty attack path (no steps)"

        chain_parts = ["Agent"]
        for step in path.steps:
            resource_short = self._short_arn(step.resource)
            chain_parts.append(f"{step.action} ({resource_short})")

        chain = " -> ".join(chain_parts)

        # Final privilege summary
        final_privilege = path.steps[-1].privilege_gained if path.steps else "Unknown"

        explanation = (
            f"{chain}\n"
            f"  Result: {final_privilege}\n"
            f"  Description: {path.description}\n"
            f"  Likelihood: {path.likelihood:.2f} | "
            f"Impact: {path.impact:.2f} | "
            f"Score: {path.composite_score:.1f}/100"
        )

        return explanation

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

    def _find_resources_for_actions(
        self,
        permissions: list[EffectivePermission],
        target_actions: set[str],
    ) -> list[str]:
        """
        Find unique resources associated with specific actions.

        Args:
            permissions: List of effective permissions.
            target_actions: Set of action strings to match.

        Returns:
            Deduplicated list of resource ARNs/patterns.
        """
        resources = set()
        for perm in permissions:
            if perm.action in target_actions:
                resources.add(perm.resource)
        return list(resources) if resources else ["*"]

    def _short_arn(self, arn: str) -> str:
        """
        Shorten an ARN for display purposes.

        Extracts the meaningful suffix from a full ARN to improve readability
        in path explanations.

        Args:
            arn: Full ARN string or wildcard.

        Returns:
            Shortened representation.
        """
        if arn == "*":
            return "*"
        if not arn.startswith("arn:"):
            return arn

        parts = arn.split(":")
        if len(parts) >= 6:
            # Return service:resource portion
            resource_part = ":".join(parts[5:])
            if len(resource_part) > 50:
                return f"...{resource_part[-47:]}"
            return resource_part
        return arn
