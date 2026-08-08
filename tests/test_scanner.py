"""
tests/test_scanner.py
─────────────────────────────────────────────────────────────────────────────
Unit tests for the static IAM policy scanner.

Each test targets a specific rule and verifies both positive (should fire)
and negative (should NOT fire) cases. Tests are grouped by rule category.
"""

import pytest

from aws_agent_identity_guard import scan_policy_document, scan_trust_policy

# ═══════════════════════════════════════════════════════════════════════════════
# ORIGINAL RULES (AIG001–AIG007)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAIG001NotActionNotResource:
    """AIG001: NotAction/NotResource grants everything except the listed items."""

    def test_not_action_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "NotAction": "s3:DeleteBucket",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG001" for f in findings)

    def test_not_resource_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "NotResource": "arn:aws:s3:::sensitive-bucket/*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG001" for f in findings)

    def test_normal_action_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::my-bucket/*",
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG001" for f in findings)


class TestAIG002WildcardActions:
    """AIG002: Wildcard service or full-account actions."""

    def test_star_action_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG002" for f in findings)

    def test_service_wildcard_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:*",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG002" for f in findings)

    def test_specific_action_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG002" for f in findings)


class TestAIG003WildcardResources:
    """AIG003: Resource: '*' in agent policies."""

    def test_star_resource_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG003" for f in findings)

    def test_scoped_resource_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": "arn:aws:lambda:us-east-1:111122223333:function:my-tool",
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG003" for f in findings)


class TestAIG004PassRoleConstraint:
    """AIG004: iam:PassRole without iam:PassedToService condition."""

    def test_unconstrained_passrole_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG004" for f in findings)

    def test_constrained_passrole_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": "arn:aws:iam::111122223333:role/bedrock-agent-role",
                        "Condition": {
                            "StringEquals": {"iam:PassedToService": "bedrock.amazonaws.com"}
                        },
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG004" for f in findings)


class TestAIG005PrivilegeEscalation:
    """AIG005: IAM privilege-management actions in agent policies."""

    def test_iam_star_fires(self):
        """iam:* triggers AIG002 (wildcard action) — the broader catch-all."""
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:*",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG002" for f in findings)

    def test_attach_role_policy_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:AttachRolePolicy",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG005" for f in findings)

    def test_read_only_iam_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:ListRoles", "iam:GetRole"],
                        "Resource": "*",
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG005" for f in findings)


class TestAIG006ToolExecutionScope:
    """AIG006: Tool execution actions without resource scoping."""

    def test_lambda_invoke_star_resource_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG006" for f in findings)

    def test_scoped_lambda_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": "arn:aws:lambda:us-east-1:111122223333:function:agent-tool-search",  # noqa: E501
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG006" for f in findings)


class TestAIG007SensitiveDataAccess:
    """AIG007: Sensitive data access without principal/resource tag conditions."""

    def test_secrets_without_tags_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "arn:aws:secretsmanager:us-east-1:111122223333:secret:agent/db",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG007" for f in findings)
        assert all(f.severity == "medium" for f in findings if f.rule_id == "AIG007")

    def test_secrets_with_principal_tag_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "arn:aws:secretsmanager:us-east-1:111122223333:secret:agent/db",
                        "Condition": {"StringEquals": {"aws:PrincipalTag/tenant": "acme-corp"}},
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG007" for f in findings)


# ═══════════════════════════════════════════════════════════════════════════════
# NEW RULES (AIG008–AIG018) — Agent-specific escalation patterns
# ═══════════════════════════════════════════════════════════════════════════════


class TestAIG008BedrockControlPlane:
    """AIG008: Agent can modify its own Bedrock agent/guardrails/KB."""

    def test_create_agent_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:CreateAgent",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG008" for f in findings)
        assert any(f.severity == "critical" for f in findings if f.rule_id == "AIG008")

    def test_delete_guardrail_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:DeleteGuardrail",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG008" for f in findings)

    def test_invoke_model_does_not_fire(self):
        """Data-plane (InvokeModel) should NOT trigger control-plane rule."""
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",  # noqa: E501
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG008" for f in findings)


class TestAIG009SageMakerControlPlane:
    """AIG009: Agent can deploy endpoints or start training jobs."""

    def test_create_endpoint_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sagemaker:CreateEndpoint",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG009" for f in findings)

    def test_create_notebook_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sagemaker:CreateNotebookInstance",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG009" for f in findings)

    def test_invoke_endpoint_does_not_fire(self):
        """Runtime invocation is fine — the agent needs to call the model."""
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sagemaker-runtime:InvokeEndpoint",
                        "Resource": "arn:aws:sagemaker:us-east-1:111122223333:endpoint/my-model-v2",
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG009" for f in findings)


class TestAIG010NetworkEgress:
    """AIG010: Agent can create network interfaces or modify security groups."""

    def test_create_network_interface_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "ec2:CreateNetworkInterface",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG010" for f in findings)

    def test_authorize_egress_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "ec2:AuthorizeSecurityGroupEgress",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG010" for f in findings)


class TestAIG011AntiForensics:
    """AIG011: Agent can tamper with audit trails (CloudTrail, GuardDuty, etc.)."""

    def test_stop_logging_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "cloudtrail:StopLogging",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG011" for f in findings)
        assert any(f.severity == "critical" for f in findings if f.rule_id == "AIG011")

    def test_delete_detector_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "guardduty:DeleteDetector",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG011" for f in findings)

    def test_read_only_trail_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["cloudtrail:LookupEvents", "cloudtrail:GetTrailStatus"],
                        "Resource": "*",
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG011" for f in findings)


class TestAIG012ExcessiveActionBreadth:
    """AIG012: Single statement with > 15 distinct actions."""

    def test_many_actions_fires(self):
        # 20 distinct actions in one statement = probably copied from human role
        actions = [f"service{i}:Action{i}" for i in range(20)]
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": actions,
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG012" for f in findings)

    def test_few_actions_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                        "Resource": "arn:aws:s3:::my-bucket/*",
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG012" for f in findings)


class TestAIG013NoConditionKeys:
    """AIG013: Resource: '*' with zero Condition keys."""

    def test_no_conditions_with_star_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG013" for f in findings)

    def test_with_condition_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                        "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG013" for f in findings)

    def test_scoped_resource_does_not_fire(self):
        """Specific ARN means blast radius is already limited."""
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::my-bucket/agent-workspace/*",
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG013" for f in findings)


class TestAIG014S3WriteWithoutPrefix:
    """AIG014: S3 write/delete without key-prefix scoping."""

    def test_put_object_star_resource_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG014" for f in findings)

    def test_put_object_bucket_wildcard_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::my-bucket/*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG014" for f in findings)

    def test_put_object_with_prefix_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::my-bucket/agent-workspace/tenant-123/uploads",
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG014" for f in findings)


class TestAIG015BedrockModelScoping:
    """AIG015: Bedrock InvokeModel without model-ID resource scoping."""

    def test_invoke_model_star_resource_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG015" for f in findings)

    def test_invoke_model_specific_model_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",  # noqa: E501
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG015" for f in findings)


class TestAIG016LambdaFunctionScope:
    """AIG016: Lambda invoke without function-name resource scoping."""

    def test_invoke_star_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG016" for f in findings)

    def test_invoke_specific_function_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": "arn:aws:lambda:us-east-1:111122223333:function:agent-tool-search",  # noqa: E501
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG016" for f in findings)


class TestAIG017AssumeRoleSessionTags:
    """AIG017: sts:AssumeRole without session tag requirements."""

    def test_assume_role_no_tags_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": "arn:aws:iam::111122223333:role/downstream-role",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG017" for f in findings)

    def test_assume_role_with_request_tags_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": "arn:aws:iam::111122223333:role/downstream-role",
                        "Condition": {
                            "StringEquals": {
                                "aws:RequestTag/agent-session-id": "${aws:PrincipalTag/session-id}"
                            },
                            "ForAllValues:StringEquals": {
                                "sts:TransitiveTagKeys": ["agent-session-id", "tenant"]
                            },
                        },
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG017" for f in findings)


class TestAIG018DatabaseFullAccess:
    """AIG018: Database scan/query without row-level conditions."""

    def test_dynamodb_scan_star_fires(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "dynamodb:Scan",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert any(f.rule_id == "AIG018" for f in findings)

    def test_dynamodb_with_leading_keys_does_not_fire(self):
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "dynamodb:Query",
                        "Resource": "*",
                        "Condition": {
                            "ForAllValues:StringEquals": {
                                "dynamodb:LeadingKeys": ["tenant#${aws:PrincipalTag/tenant}"]
                            }
                        },
                    }
                ]
            }
        )
        assert not any(f.rule_id == "AIG018" for f in findings)


# ═══════════════════════════════════════════════════════════════════════════════
# TRUST POLICY RULES (AIG-TP001–TP003)
# ═══════════════════════════════════════════════════════════════════════════════


class TestTrustPolicyRules:
    """Trust policy analysis for AssumeRolePolicyDocument."""

    def test_wildcard_principal_is_critical(self):
        findings = scan_trust_policy(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        assert any(f.rule_id == "AIG-TP001" and f.severity == "critical" for f in findings)

    def test_cross_account_missing_external_id(self):
        findings = scan_trust_policy(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        assert any(f.rule_id == "AIG-TP002" for f in findings)

    def test_cross_account_missing_source_arn(self):
        findings = scan_trust_policy(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                        "Action": "sts:AssumeRole",
                        "Condition": {"StringEquals": {"sts:ExternalId": "abc-123"}},
                    }
                ],
            }
        )
        assert "AIG-TP002" not in {f.rule_id for f in findings}
        assert any(f.rule_id == "AIG-TP003" for f in findings)

    def test_well_formed_cross_account_passes(self):
        findings = scan_trust_policy(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "StringEquals": {
                                "sts:ExternalId": "unique-secret",
                                "aws:SourceArn": "arn:aws:iam::999988887777:role/trusted",
                            }
                        },
                    }
                ],
            }
        )
        tp_findings = [f for f in findings if f.rule_id.startswith("AIG-TP")]
        assert tp_findings == []

    def test_service_principal_does_not_trigger_cross_account(self):
        """Service principals (e.g., bedrock.amazonaws.com) are not cross-account."""
        findings = scan_trust_policy(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "bedrock.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        # Service principal should not trigger TP002 or TP003
        assert not any(f.rule_id in ("AIG-TP002", "AIG-TP003") for f in findings)

    def test_malformed_input_raises_type_error(self):
        with pytest.raises(TypeError, match="trust policy document must be a dict"):
            scan_trust_policy("not a dict")  # type: ignore[arg-type]


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS — Realistic Agent Policies
# ═══════════════════════════════════════════════════════════════════════════════


class TestRealisticAgentPolicies:
    """End-to-end tests with realistic agent policy documents."""

    def test_well_scoped_bedrock_agent_passes(self):
        """A properly scoped Bedrock agent policy should produce only low/medium findings."""
        findings = scan_policy_document(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "InvokeModel",
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",  # noqa: E501
                    },
                    {
                        "Sid": "InvokeTool",
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": "arn:aws:lambda:us-east-1:111122223333:function:agent-tool-*",
                        "Condition": {
                            "StringEquals": {"aws:PrincipalTag/agent-owner": "security-team"}
                        },
                    },
                    {
                        "Sid": "ReadSecrets",
                        "Effect": "Allow",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "arn:aws:secretsmanager:us-east-1:111122223333:secret:agent/*",
                        "Condition": {
                            "StringEquals": {"aws:ResourceTag/tenant": "${aws:PrincipalTag/tenant}"}
                        },
                    },
                ],
            }
        )
        # Should have zero high/critical findings
        severe = [f for f in findings if f.severity in ("critical", "high")]
        assert severe == [], f"Expected no severe findings, got: {severe}"

    def test_overprivileged_agent_has_many_findings(self):
        """A classic 'just give it admin' agent policy should light up like a Christmas tree."""
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "bedrock:*",
                            "lambda:InvokeFunction",
                            "iam:PassRole",
                            "iam:AttachRolePolicy",
                            "s3:*",
                            "secretsmanager:GetSecretValue",
                            "cloudtrail:StopLogging",
                            "sagemaker:CreateEndpoint",
                            "ec2:CreateNetworkInterface",
                            "dynamodb:Scan",
                            "sts:AssumeRole",
                        ],
                        "Resource": "*",
                    }
                ]
            }
        )
        rule_ids = {f.rule_id for f in findings}
        # Should fire many rules
        assert "AIG002" in rule_ids  # bedrock:* is wildcard
        assert "AIG003" in rule_ids  # Resource: *
        assert "AIG004" in rule_ids  # PassRole without condition
        assert "AIG005" in rule_ids  # AttachRolePolicy = privilege escalation
        assert "AIG006" in rule_ids  # Lambda invoke with Resource: *
        assert "AIG007" in rule_ids  # secrets without tags
        assert "AIG009" in rule_ids  # SageMaker CreateEndpoint
        assert "AIG010" in rule_ids  # EC2 CreateNetworkInterface
        assert "AIG011" in rule_ids  # CloudTrail StopLogging
        assert "AIG013" in rule_ids  # No conditions + Resource: *

    def test_deny_statements_are_ignored(self):
        """Deny statements should not generate findings — they restrict, not grant."""
        findings = scan_policy_document(
            {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*",
                    }
                ]
            }
        )
        assert findings == []

    def test_empty_policy_passes(self):
        findings = scan_policy_document({"Statement": []})
        assert findings == []

    def test_type_error_on_non_dict(self):
        with pytest.raises(TypeError):
            scan_policy_document("not a policy")  # type: ignore[arg-type]
