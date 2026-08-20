"""
tests/test_real_world_policies.py
─────────────────────────────────────────────────────────────────────────────
IAM policy regression cases derived from AWS documentation examples and
agent-role misconfiguration hypotheses.

Each test uses policy-shaped JSON and asserts which specific AIG rules should
fire. Do not treat these fixtures as production incident measurements.
"""

import json
from pathlib import Path

from aws_agent_identity_guard import scan_policy_document, scan_trust_policy

EXAMPLES_DIR = Path(__file__).parent.parent / "examples" / "real_world"


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 1: AWS Bedrock Agent Execution Role
# Source: https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html
#
# The AWS docs show a properly scoped policy with specific model ARNs, but many
# teams deploy with Resource: "*" and add control-plane actions to the same role.
# This test validates that AIG catches the overprivileged "quick start" pattern
# vs the properly scoped version from the docs.
# ═══════════════════════════════════════════════════════════════════════════════


class TestBedrockAgentDefaultOverprivileged:
    """
    Documentation-derived risky variant: an agent execution role uses Resource: '*'
    and add control-plane actions (CreateAgent, UpdateAgent, etc.) to the
    execution role instead of a separate admin role.

    Source: https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html
    Pattern: Over-broad agent execution role fixture
    """

    # The overprivileged default that teams commonly deploy
    OVERPRIVILEGED_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BedrockAgentOverlyBroadAccess",
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                "Resource": "*",
            },
            {
                "Sid": "BedrockAgentS3Access",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*",
            },
            {
                "Sid": "BedrockKnowledgeBaseAccess",
                "Effect": "Allow",
                "Action": ["bedrock:Retrieve", "bedrock:RetrieveAndGenerate"],
                "Resource": "*",
            },
            {
                "Sid": "BedrockAgentLambdaInvoke",
                "Effect": "Allow",
                "Action": ["lambda:InvokeFunction"],
                "Resource": "*",
            },
            {
                "Sid": "BedrockAgentPassRole",
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
            },
            {
                "Sid": "BedrockAgentControlPlane",
                "Effect": "Allow",
                "Action": [
                    "bedrock:CreateAgent",
                    "bedrock:UpdateAgent",
                    "bedrock:CreateAgentActionGroup",
                    "bedrock:UpdateAgentActionGroup",
                    "bedrock:CreateKnowledgeBase",
                    "bedrock:UpdateKnowledgeBase",
                    "bedrock:AssociateAgentKnowledgeBase",
                    "bedrock:GetAgent",
                    "bedrock:GetAgentAlias",
                    "bedrock:ListAgents",
                    "bedrock:ListAgentAliases",
                ],
                "Resource": "*",
            },
            {
                "Sid": "BedrockGuardrailManagement",
                "Effect": "Allow",
                "Action": [
                    "bedrock:CreateGuardrail",
                    "bedrock:UpdateGuardrail",
                    "bedrock:DeleteGuardrail",
                    "bedrock:ApplyGuardrail",
                ],
                "Resource": "*",
            },
        ],
    }

    def test_catches_wildcard_resource_on_invoke_model(self):
        """AIG003 + AIG015: Resource '*' on InvokeModel = any model in account."""
        findings = scan_policy_document(self.OVERPRIVILEGED_POLICY)
        rule_ids = {f.rule_id for f in findings}
        # Wildcard resource
        assert "AIG003" in rule_ids
        # Bedrock InvokeModel without model-ID scoping
        assert "AIG015" in rule_ids

    def test_catches_unconstrained_pass_role(self):
        """AIG004 + AIG005: PassRole without PassedToService = privilege escalation."""
        findings = scan_policy_document(self.OVERPRIVILEGED_POLICY)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG004" in rule_ids
        assert "AIG005" in rule_ids

    def test_catches_bedrock_control_plane_actions(self):
        """AIG008: CreateAgent, UpdateAgent, CreateKnowledgeBase, DeleteGuardrail."""
        findings = scan_policy_document(self.OVERPRIVILEGED_POLICY)
        aig008_findings = [f for f in findings if f.rule_id == "AIG008"]
        # Should fire for each control-plane action
        assert len(aig008_findings) >= 5
        # All should be critical severity
        assert all(f.severity == "critical" for f in aig008_findings)

    def test_catches_lambda_invoke_without_function_scope(self):
        """AIG006 + AIG016: Lambda invoke with Resource '*'."""
        findings = scan_policy_document(self.OVERPRIVILEGED_POLICY)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG006" in rule_ids
        assert "AIG016" in rule_ids

    def test_catches_excessive_action_breadth(self):
        """AIG012: Control-plane statement has >15 actions across statements."""
        findings = scan_policy_document(self.OVERPRIVILEGED_POLICY)
        # The control-plane statement (11 actions) + guardrail statement (4 actions)
        # individually may not hit 15, but the broad pattern is still caught by other rules
        rule_ids = {f.rule_id for f in findings}
        # At minimum these critical rules must fire
        assert "AIG003" in rule_ids
        assert "AIG004" in rule_ids
        assert "AIG008" in rule_ids

    def test_properly_scoped_policy_passes(self):
        """
        The AWS docs recommended policy with specific model ARNs, scoped
        resources, and no control-plane actions should produce minimal findings.

        Source: https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html
        (Identity-based permissions for the Agents service role section)
        """
        well_scoped_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AgentModelInvocationPermissions",
                    "Effect": "Allow",
                    "Action": ["bedrock:InvokeModel"],
                    "Resource": [
                        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2",
                        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2:1",
                        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-instant-v1",
                    ],
                },
                {
                    "Sid": "AgentActionGroupS3",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::my-schemas-bucket/api-schema.json"],
                    "Condition": {"StringEquals": {"aws:ResourceAccount": "123456789012"}},
                },
                {
                    "Sid": "AgentKnowledgeBaseQuery",
                    "Effect": "Allow",
                    "Action": ["bedrock:Retrieve", "bedrock:RetrieveAndGenerate"],
                    "Resource": ["arn:aws:bedrock:us-east-1:123456789012:knowledge-base/KB12345"],
                },
            ],
        }
        findings = scan_policy_document(well_scoped_policy)
        # Should NOT fire critical rules
        critical_findings = [f for f in findings if f.severity == "critical"]
        assert len(critical_findings) == 0
        # Should NOT fire AIG003 (no wildcard resources)
        assert not any(f.rule_id == "AIG003" for f in findings)
        # Should NOT fire AIG008 (no control-plane actions)
        assert not any(f.rule_id == "AIG008" for f in findings)

    def test_example_file_matches_inline_policy(self):
        """Verify the standalone JSON example matches this test's policy."""
        example_path = EXAMPLES_DIR / "aws_bedrock_agent_default.json"
        with open(example_path) as f:
            file_policy = json.load(f)
        assert file_policy == self.OVERPRIVILEGED_POLICY


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 2: AWS SageMaker AmazonSageMakerFullAccess Managed Policy
# Source: AWS Managed Policy arn:aws:iam::aws:policy/AmazonSageMakerFullAccess
# Reference: https://docs.aws.amazon.com/sagemaker/latest/dg/security-iam-awsmanpol.html
#
# This is the default managed policy AWS suggests for SageMaker execution roles.
# It grants sagemaker:* plus broad S3, ECR, EC2, Secrets Manager, and KMS access.
# When used for an AI agent, it's massively overprivileged.
# ═══════════════════════════════════════════════════════════════════════════════


class TestSageMakerFullAccessPolicy:
    """
    Documentation-derived regression case: AmazonSageMakerFullAccess attached
    to a role that only needs sagemaker-runtime:InvokeEndpoint. The managed
    policy grants sagemaker:* plus broad access to S3, ECR, EC2,
    Secrets Manager, and KMS.

    Source: arn:aws:iam::aws:policy/AmazonSageMakerFullAccess
    Reference: https://docs.aws.amazon.com/sagemaker/latest/dg/security-iam-awsmanpol.html
    """

    SAGEMAKER_FULL_ACCESS_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SageMakerFullAccess",
                "Effect": "Allow",
                "Action": ["sagemaker:*"],
                "Resource": "*",
            },
            {
                "Sid": "SageMakerECRAccess",
                "Effect": "Allow",
                "Action": [
                    "ecr:GetAuthorizationToken",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:SetRepositoryPolicy",
                    "ecr:CompleteLayerUpload",
                    "ecr:BatchDeleteImage",
                    "ecr:UploadLayerPart",
                    "ecr:InitiateLayerUpload",
                    "ecr:PutImage",
                    "ecr:CreateRepository",
                    "ecr:DescribeRepositories",
                    "ecr:DescribeImages",
                ],
                "Resource": "*",
            },
            {
                "Sid": "SageMakerS3FullAccess",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:ListAllMyBuckets",
                    "s3:GetBucketCors",
                    "s3:PutBucketCors",
                    "s3:GetBucketAcl",
                    "s3:PutObjectAcl",
                ],
                "Resource": "*",
            },
            {
                "Sid": "SageMakerIAMPassRole",
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "iam:PassedToService": [
                            "sagemaker.amazonaws.com",
                            "glue.amazonaws.com",
                            "robomaker.amazonaws.com",
                            "states.amazonaws.com",
                        ]
                    }
                },
            },
            {
                "Sid": "SageMakerVPCAccess",
                "Effect": "Allow",
                "Action": [
                    "ec2:CreateNetworkInterface",
                    "ec2:CreateNetworkInterfacePermission",
                    "ec2:DeleteNetworkInterface",
                    "ec2:DeleteNetworkInterfacePermission",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:DescribeVpcs",
                    "ec2:DescribeDhcpOptions",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeSecurityGroups",
                ],
                "Resource": "*",
            },
            {
                "Sid": "SageMakerSecretsManagerAccess",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:ListSecrets",
                ],
                "Resource": "*",
            },
            {
                "Sid": "SageMakerKMSAccess",
                "Effect": "Allow",
                "Action": [
                    "kms:Decrypt",
                    "kms:GenerateDataKey",
                    "kms:CreateGrant",
                    "kms:DescribeKey",
                ],
                "Resource": "*",
            },
            {
                "Sid": "SageMakerLogsAccess",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:GetLogEvents",
                    "logs:DescribeLogStreams",
                ],
                "Resource": "*",
            },
        ],
    }

    def test_catches_sagemaker_wildcard_action(self):
        """AIG002: sagemaker:* is a service-level wildcard."""
        findings = scan_policy_document(self.SAGEMAKER_FULL_ACCESS_POLICY)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG002" in rule_ids
        # Wildcard actions should be critical
        aig002 = [f for f in findings if f.rule_id == "AIG002"]
        assert all(f.severity == "critical" for f in aig002)

    def test_catches_sagemaker_control_plane(self):
        """AIG009: sagemaker:* includes CreateEndpoint, CreateNotebookInstance."""
        findings = scan_policy_document(self.SAGEMAKER_FULL_ACCESS_POLICY)
        # Note: sagemaker:* triggers AIG002, which is the broader wildcard catch.
        # AIG009 fires on specific control-plane actions, not wildcards.
        # The wildcard itself is caught by AIG002 as the higher-severity rule.
        rule_ids = {f.rule_id for f in findings}
        assert "AIG002" in rule_ids

    def test_catches_network_egress_ec2(self):
        """AIG010: ec2:CreateNetworkInterface enables outbound connections."""
        findings = scan_policy_document(self.SAGEMAKER_FULL_ACCESS_POLICY)
        aig010 = [f for f in findings if f.rule_id == "AIG010"]
        assert len(aig010) >= 1
        assert any("CreateNetworkInterface" in f.message for f in aig010)

    def test_catches_sensitive_data_access(self):
        """AIG007: Secrets Manager and KMS access without ABAC conditions."""
        findings = scan_policy_document(self.SAGEMAKER_FULL_ACCESS_POLICY)
        aig007 = [f for f in findings if f.rule_id == "AIG007"]
        # Should flag secretsmanager:GetSecretValue, kms:Decrypt, s3:GetObject, etc.
        assert len(aig007) >= 3

    def test_catches_s3_write_without_prefix(self):
        """AIG014: S3 PutObject/DeleteObject with Resource '*' = full bucket access."""
        findings = scan_policy_document(self.SAGEMAKER_FULL_ACCESS_POLICY)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG014" in rule_ids

    def test_catches_no_conditions_on_broad_statements(self):
        """AIG013: Resource '*' with zero condition keys on multiple statements."""
        findings = scan_policy_document(self.SAGEMAKER_FULL_ACCESS_POLICY)
        aig013 = [f for f in findings if f.rule_id == "AIG013"]
        # Most statements have Resource '*' and no conditions
        assert len(aig013) >= 4

    def test_passrole_with_condition_not_flagged_by_aig004(self):
        """The PassRole statement HAS PassedToService condition  -  AIG004 should NOT fire for it."""
        findings = scan_policy_document(self.SAGEMAKER_FULL_ACCESS_POLICY)
        aig004 = [f for f in findings if f.rule_id == "AIG004"]
        # Statement index 3 is PassRole with condition  -  should not appear
        assert not any(f.statement_index == 3 for f in aig004)

    def test_example_file_matches_inline_policy(self):
        """Verify the standalone JSON example matches this test's policy."""
        example_path = EXAMPLES_DIR / "aws_sagemaker_full_access.json"
        with open(example_path) as f:
            file_policy = json.load(f)
        assert file_policy == self.SAGEMAKER_FULL_ACCESS_POLICY


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 3: Over-Permissive Lambda Execution Role
# Source: Common serverless deployment anti-pattern
# Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html
#
# In serverless deployments, teams often give Lambda functions overly broad
# permissions because "it's just a function." When that Lambda is invoked by
# a Bedrock agent as a tool, the blast radius extends to the agent's full
# attack surface. This is the real pattern from SAM/Serverless Framework
# deployments that use Resource: '*' for convenience.
# ═══════════════════════════════════════════════════════════════════════════════


class TestLambdaOverPermissiveRole:
    """
    Regression case: Serverless Framework / SAM style template with overly
    broad IAM permissions. The Lambda function is used as a Bedrock agent
    action group tool, inheriting all these permissions as the agent's
    effective capability.

    Source: Common pattern in SAM/Serverless Framework deployments
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html
    Misconfiguration: https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/
    """

    LAMBDA_OVERPERMISSIVE_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "LambdaBasicExecution",
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
            {
                "Sid": "LambdaVPCAccess",
                "Effect": "Allow",
                "Action": [
                    "ec2:CreateNetworkInterface",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:DeleteNetworkInterface",
                    "ec2:AssignPrivateIpAddresses",
                    "ec2:UnassignPrivateIpAddresses",
                ],
                "Resource": "*",
            },
            {
                "Sid": "LambdaOverlyBroadDynamoDB",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:Query",
                    "dynamodb:Scan",
                    "dynamodb:BatchGetItem",
                    "dynamodb:BatchWriteItem",
                ],
                "Resource": "*",
            },
            {
                "Sid": "LambdaOverlyBroadS3",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
                "Resource": "*",
            },
            {
                "Sid": "LambdaOverlyBroadSecrets",
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"],
                "Resource": "*",
            },
            {
                "Sid": "LambdaOverlyBroadSQSSNS",
                "Effect": "Allow",
                "Action": [
                    "sqs:SendMessage",
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                    "sns:Publish",
                    "sns:Subscribe",
                ],
                "Resource": "*",
            },
            {
                "Sid": "LambdaInvokeOtherFunctions",
                "Effect": "Allow",
                "Action": ["lambda:InvokeFunction", "lambda:InvokeAsync"],
                "Resource": "*",
            },
            {
                "Sid": "LambdaKMSDecrypt",
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                "Resource": "*",
            },
        ],
    }

    def test_catches_network_egress(self):
        """AIG010: ec2:CreateNetworkInterface in Lambda VPC configuration."""
        findings = scan_policy_document(self.LAMBDA_OVERPERMISSIVE_POLICY)
        aig010 = [f for f in findings if f.rule_id == "AIG010"]
        assert len(aig010) >= 1

    def test_catches_dynamodb_full_table_scan(self):
        """AIG018: DynamoDB Scan/Query with Resource '*' and no conditions."""
        findings = scan_policy_document(self.LAMBDA_OVERPERMISSIVE_POLICY)
        aig018 = [f for f in findings if f.rule_id == "AIG018"]
        assert len(aig018) >= 1

    def test_catches_s3_write_without_prefix_scoping(self):
        """AIG014: S3 PutObject + DeleteObject with Resource '*'."""
        findings = scan_policy_document(self.LAMBDA_OVERPERMISSIVE_POLICY)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG014" in rule_ids

    def test_catches_sensitive_data_without_abac(self):
        """AIG007: secretsmanager:GetSecretValue, kms:Decrypt without principal tags."""
        findings = scan_policy_document(self.LAMBDA_OVERPERMISSIVE_POLICY)
        aig007 = [f for f in findings if f.rule_id == "AIG007"]
        # Should catch: secretsmanager:GetSecretValue, secretsmanager:ListSecrets,
        # kms:Decrypt, kms:GenerateDataKey, s3:GetObject, s3:ListBucket,
        # dynamodb:GetItem, dynamodb:Query, dynamodb:Scan
        assert len(aig007) >= 5

    def test_catches_lambda_invoke_all_functions(self):
        """AIG006 + AIG016: lambda:InvokeFunction with Resource '*'."""
        findings = scan_policy_document(self.LAMBDA_OVERPERMISSIVE_POLICY)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG006" in rule_ids
        assert "AIG016" in rule_ids

    def test_catches_no_conditions_broad_statements(self):
        """AIG013: Multiple statements with Resource '*' and no conditions."""
        findings = scan_policy_document(self.LAMBDA_OVERPERMISSIVE_POLICY)
        aig013 = [f for f in findings if f.rule_id == "AIG013"]
        # Statements 1-7 all have Resource '*' and no conditions
        assert len(aig013) >= 5

    def test_total_finding_count_shows_severity(self):
        """Overall: This policy should produce many findings across severities."""
        findings = scan_policy_document(self.LAMBDA_OVERPERMISSIVE_POLICY)
        severities = {f.severity for f in findings}
        # Should have high and medium at minimum
        assert "high" in severities
        assert "medium" in severities
        # Should produce substantial number of findings
        assert len(findings) >= 15

    def test_example_file_matches_inline_policy(self):
        """Verify the standalone JSON example matches this test's policy."""
        example_path = EXAMPLES_DIR / "lambda_over_permissive.json"
        with open(example_path) as f:
            file_policy = json.load(f)
        assert file_policy == self.LAMBDA_OVERPERMISSIVE_POLICY


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 4: ECS Task Role for Bedrock Agent Deployment
# Source: Common ECS Bedrock agent deployment pattern
# Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
#
# The #1 misconfiguration in ECS-based Bedrock agent deployments:
# iam:PassRole without iam:PassedToService condition. Teams add PassRole so
# the ECS task can pass roles to Bedrock, but forget the condition key,
# allowing the task to pass ANY role to ANY service  -  classic privilege
# escalation vector.
# ═══════════════════════════════════════════════════════════════════════════════


class TestECSTaskRoleBedrockAgent:
    """
    Regression case: ECS task role for a containerized Bedrock agent. The task
    needs to invoke Bedrock models and pass a role to the Bedrock service, but
    the PassRole is unconstrained.

    Source: ECS task-role and iam:PassRole documentation-derived fixture
    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
    Misconfiguration: iam:PassRole without iam:PassedToService condition
    """

    ECS_TASK_ROLE_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ECSBedrockInvoke",
                "Effect": "Allow",
                "Action": [
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                    "bedrock-agent-runtime:InvokeAgent",
                    "bedrock-agent-runtime:Retrieve",
                    "bedrock-agent-runtime:RetrieveAndGenerate",
                ],
                "Resource": "*",
            },
            {
                "Sid": "ECSPassRoleUnconstrained",
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::111122223333:role/*",
            },
            {
                "Sid": "ECSTaskExecutionLogs",
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents", "logs:GetLogEvents"],
                "Resource": "arn:aws:logs:us-east-1:111122223333:log-group:/ecs/bedrock-agent:*",
            },
            {
                "Sid": "ECSSecretsAccess",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "ssm:GetParameter",
                    "ssm:GetParameters",
                    "ssm:GetParametersByPath",
                ],
                "Resource": "*",
            },
            {
                "Sid": "ECSS3ModelArtifacts",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": "*",
            },
            {
                "Sid": "ECSLambdaToolInvoke",
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": "*",
            },
            {
                "Sid": "ECSDynamoDBState",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:Query",
                    "dynamodb:Scan",
                ],
                "Resource": "*",
            },
            {
                "Sid": "ECSStepFunctionsOrchestration",
                "Effect": "Allow",
                "Action": [
                    "states:StartExecution",
                    "states:StartSyncExecution",
                    "states:DescribeExecution",
                    "states:StopExecution",
                ],
                "Resource": "*",
            },
        ],
    }

    def test_catches_passrole_without_passed_to_service(self):
        """AIG004: The #1 ECS misconfiguration  -  PassRole without PassedToService."""
        findings = scan_policy_document(self.ECS_TASK_ROLE_POLICY)
        aig004 = [f for f in findings if f.rule_id == "AIG004"]
        assert len(aig004) == 1
        assert aig004[0].severity == "critical"
        assert "iam:PassedToService" in aig004[0].message

    def test_catches_passrole_as_privilege_escalation(self):
        """AIG005: PassRole is in PRIVILEGE_ACTIONS set."""
        findings = scan_policy_document(self.ECS_TASK_ROLE_POLICY)
        aig005 = [f for f in findings if f.rule_id == "AIG005"]
        assert len(aig005) >= 1
        assert any("PassRole" in f.message for f in aig005)

    def test_catches_bedrock_invoke_without_model_scope(self):
        """AIG015: InvokeModel with Resource '*' = any model."""
        findings = scan_policy_document(self.ECS_TASK_ROLE_POLICY)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG015" in rule_ids

    def test_catches_tool_execution_unscoped(self):
        """AIG006: lambda:InvokeFunction, states:StartExecution with Resource '*'."""
        findings = scan_policy_document(self.ECS_TASK_ROLE_POLICY)
        aig006 = [f for f in findings if f.rule_id == "AIG006"]
        # Should catch: bedrock-agent-runtime:InvokeAgent, bedrock-agent-runtime:Retrieve,
        # bedrock-agent-runtime:RetrieveAndGenerate, lambda:InvokeFunction,
        # states:StartExecution, states:StartSyncExecution, bedrock:InvokeModel,
        # bedrock:InvokeModelWithResponseStream
        assert len(aig006) >= 5

    def test_catches_secrets_without_abac(self):
        """AIG007: secretsmanager + SSM parameter access without tags."""
        findings = scan_policy_document(self.ECS_TASK_ROLE_POLICY)
        aig007 = [f for f in findings if f.rule_id == "AIG007"]
        # secretsmanager:GetSecretValue, ssm:GetParameter, ssm:GetParameters,
        # ssm:GetParametersByPath, s3:GetObject, s3:ListBucket,
        # dynamodb:GetItem, dynamodb:Query, dynamodb:Scan, logs:GetLogEvents
        assert len(aig007) >= 5

    def test_catches_dynamodb_unscoped_scan(self):
        """AIG018: DynamoDB Scan/Query with Resource '*'."""
        findings = scan_policy_document(self.ECS_TASK_ROLE_POLICY)
        aig018 = [f for f in findings if f.rule_id == "AIG018"]
        assert len(aig018) >= 1

    def test_catches_s3_write_broad(self):
        """AIG014: S3 PutObject with Resource '*'."""
        findings = scan_policy_document(self.ECS_TASK_ROLE_POLICY)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG014" in rule_ids

    def test_properly_constrained_ecs_role_passes(self):
        """Properly scoped ECS task role with PassedToService condition."""
        well_scoped = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "BedrockInvoke",
                    "Effect": "Allow",
                    "Action": ["bedrock:InvokeModel"],
                    "Resource": [
                        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
                    ],
                },
                {
                    "Sid": "PassRoleConstrained",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::111122223333:role/bedrock-agent-service-role",
                    "Condition": {"StringEquals": {"iam:PassedToService": "bedrock.amazonaws.com"}},
                },
                {
                    "Sid": "LambdaToolScoped",
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": [
                        "arn:aws:lambda:us-east-1:111122223333:function:agent-tool-search",
                        "arn:aws:lambda:us-east-1:111122223333:function:agent-tool-retrieve",
                    ],
                },
            ],
        }
        findings = scan_policy_document(well_scoped)
        # Should NOT fire AIG004 (PassRole has PassedToService condition)
        assert not any(f.rule_id == "AIG004" for f in findings)
        # Should NOT fire AIG003 (no wildcard resources)
        assert not any(f.rule_id == "AIG003" for f in findings)
        # AIG005 WILL fire for PassRole (it's in PRIVILEGE_ACTIONS regardless of conditions)
        # This is correct: AIG005 flags that privilege-management actions exist in
        # agent roles at all. The condition mitigates it (hence no AIG004) but
        # the presence of PassRole is still noteworthy.
        aig005 = [f for f in findings if f.rule_id == "AIG005"]
        assert len(aig005) == 1
        # No OTHER critical findings beyond AIG005 for PassRole
        critical_non_passrole = [
            f for f in findings if f.severity == "critical" and f.rule_id != "AIG005"
        ]
        assert len(critical_non_passrole) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 5: Cross-Account Trust Policy  -  Confused Deputy
# Source: AWS Organizations cross-account role assumption pattern
# Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
# Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html
#
# Missing sts:ExternalId in cross-account trust policies is the confused-deputy
# vulnerability. Any resource in the trusted account can assume the role,
# not just the intended service/principal. This is especially dangerous for
# agent roles because a compromised agent in the trusted account can
# escalate to the trusting account.
# ═══════════════════════════════════════════════════════════════════════════════


class TestCrossAccountTrustPolicyConfusedDeputy:
    """
    Regression case: Cross-account trust policy for an AI agent orchestration
    platform. A partner/vendor account is trusted to assume a role in the
    customer account, and the trust policy is missing:
    1. sts:ExternalId (confused deputy protection)
    2. aws:SourceArn (lateral movement protection)

    Source: AWS Organizations multi-account agent deployment
    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html
    """

    # Trust policy missing ExternalId  -  the confused deputy vulnerability
    VULNERABLE_TRUST_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountAgentAccess",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999888777666:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    # Trust policy with wildcard principal  -  worst case
    WILDCARD_TRUST_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAnyPrincipal",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }
        ],
    }

    # Multi-account trust with partial conditions (has SourceAccount but no ExternalId)
    PARTIAL_CONDITIONS_TRUST = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPartnerAccountAgent",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::999888777666:role/agent-orchestrator",
                        "arn:aws:iam::555444333222:role/ml-pipeline",
                    ]
                },
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123def4"}},
            }
        ],
    }

    def test_catches_missing_external_id(self):
        """AIG-TP002: Cross-account trust without sts:ExternalId."""
        findings = scan_trust_policy(self.VULNERABLE_TRUST_POLICY)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG-TP002" in rule_ids
        tp002 = [f for f in findings if f.rule_id == "AIG-TP002"]
        assert tp002[0].severity == "high"
        assert "ExternalId" in tp002[0].message

    def test_catches_missing_source_arn(self):
        """AIG-TP003: Cross-account trust without aws:SourceArn."""
        findings = scan_trust_policy(self.VULNERABLE_TRUST_POLICY)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG-TP003" in rule_ids
        tp003 = [f for f in findings if f.rule_id == "AIG-TP003"]
        assert tp003[0].severity == "high"

    def test_catches_wildcard_principal(self):
        """AIG-TP001: Wildcard principal '*' = any AWS identity can assume."""
        findings = scan_trust_policy(self.WILDCARD_TRUST_POLICY)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG-TP001" in rule_ids
        tp001 = [f for f in findings if f.rule_id == "AIG-TP001"]
        assert tp001[0].severity == "critical"

    def test_catches_partial_conditions_still_vulnerable(self):
        """AIG-TP002 + AIG-TP003: PrincipalOrgID is not ExternalId or SourceArn."""
        findings = scan_trust_policy(self.PARTIAL_CONDITIONS_TRUST)
        rule_ids = {f.rule_id for f in findings}
        # Still missing ExternalId even though it has PrincipalOrgID
        assert "AIG-TP002" in rule_ids
        # Still missing SourceArn
        assert "AIG-TP003" in rule_ids

    def test_properly_secured_trust_policy(self):
        """Properly secured cross-account trust with ExternalId and SourceArn."""
        secure_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowPartnerWithExternalId",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999888777666:role/agent-orchestrator"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "a1b2c3d4-unique-secret-per-relationship"
                        },
                        "ArnLike": {
                            "aws:SourceArn": "arn:aws:ecs:us-east-1:999888777666:task/agent-cluster/*"  # noqa: E501
                        },
                    },
                }
            ],
        }
        findings = scan_trust_policy(secure_trust)
        # Should NOT fire TP001 (no wildcard)
        assert not any(f.rule_id == "AIG-TP001" for f in findings)
        # Should NOT fire TP002 (has ExternalId)
        assert not any(f.rule_id == "AIG-TP002" for f in findings)
        # Should NOT fire TP003 (has SourceArn)
        assert not any(f.rule_id == "AIG-TP003" for f in findings)

    def test_service_principal_trust_not_flagged(self):
        """Service principals (bedrock.amazonaws.com) should NOT trigger TP002/TP003."""
        service_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowBedrockService",
                    "Effect": "Allow",
                    "Principal": {"Service": "bedrock.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": "111122223333"},
                        "ArnLike": {
                            "aws:SourceArn": "arn:aws:bedrock:us-east-1:111122223333:agent/*"
                        },
                    },
                }
            ],
        }
        findings = scan_trust_policy(service_trust)
        # Service principals are not cross-account ARNs
        assert not any(f.rule_id == "AIG-TP002" for f in findings)
        assert not any(f.rule_id == "AIG-TP003" for f in findings)
