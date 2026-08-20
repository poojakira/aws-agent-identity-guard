"""Adversarial test suite.

Tests that the authorization system correctly blocks malicious scenarios:
- Privilege escalation attempts
- Credential theft scenarios
- Cross-account access
- Destructive actions
- Confused deputy attacks
- Data exfiltration
- Policy bypass attempts
"""

from __future__ import annotations

import pytest

from aws_agent_identity_guard.models import (
    DataClassification,
    Decision,
    Environment,
)
from aws_agent_identity_guard.authorization import (
    AuthorizationConfig,
    AuthorizationDecision,
    AuthorizationRequest,
    AuthorizationService,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def service() -> AuthorizationService:
    """Authorization service with default (production-secure) config."""
    return AuthorizationService(config=AuthorizationConfig())


@pytest.fixture
def strict_service() -> AuthorizationService:
    """Authorization service with strict thresholds."""
    config = AuthorizationConfig(
        deny_threshold=40,
        step_up_threshold=25,
        review_threshold=15,
    )
    return AuthorizationService(config=config)


# =============================================================================
# Test: Privilege Escalation Attempts
# =============================================================================


class TestPrivilegeEscalation:
    """Tests that privilege escalation attempts are blocked."""

    def test_create_admin_role_denied(self, service: AuthorizationService) -> None:
        """Attempt to create a new IAM role in production is denied."""
        request = AuthorizationRequest.create(
            agent_id="malicious-agent",
            agent_name="escalation-bot",
            principal="compromised@corp.com",
            action="iam:CreateRole",
            resource="arn:aws:iam::123456789012:role/backdoor-admin",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY

    def test_attach_admin_policy_denied(self, service: AuthorizationService) -> None:
        """Attempt to attach AdministratorAccess policy is denied."""
        request = AuthorizationRequest.create(
            agent_id="malicious-agent",
            agent_name="policy-attacher",
            principal="attacker@evil.com",
            action="iam:AttachRolePolicy",
            resource="arn:aws:iam::123456789012:role/agent-role",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY

    def test_update_trust_policy_denied(self, service: AuthorizationService) -> None:
        """Attempt to modify trust policy is denied."""
        request = AuthorizationRequest.create(
            agent_id="malicious-agent",
            agent_name="trust-modifier",
            principal="attacker@evil.com",
            action="iam:UpdateAssumeRolePolicy",
            resource="arn:aws:iam::123456789012:role/production-role",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.SECRET,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY

    def test_passrole_to_admin_denied(self, service: AuthorizationService) -> None:
        """Attempt to pass admin role is denied in production."""
        request = AuthorizationRequest.create(
            agent_id="escalation-agent",
            agent_name="role-passer",
            principal="user@corp.com",
            action="iam:PassRole",
            resource="arn:aws:iam::123456789012:role/admin-role",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY


# =============================================================================
# Test: Credential Theft Scenarios
# =============================================================================


class TestCredentialTheft:
    """Tests that credential theft attempts are detected/blocked."""

    def test_create_access_key_flagged(self, strict_service: AuthorizationService) -> None:
        """Creating access keys triggers deny or step-up."""
        request = AuthorizationRequest.create(
            agent_id="cred-thief",
            agent_name="key-creator",
            principal="insider@corp.com",
            action="iam:CreateAccessKey",
            resource="arn:aws:iam::123456789012:user/service-account",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.SECRET,
        )
        decision = strict_service.authorize(request)
        assert decision.decision in (Decision.DENY, Decision.STEP_UP)

    def test_get_secret_in_production_controlled(self, strict_service: AuthorizationService) -> None:
        """Accessing production secrets requires elevated authorization."""
        request = AuthorizationRequest.create(
            agent_id="secret-reader",
            agent_name="data-agent",
            principal="agent@corp.com",
            action="secretsmanager:GetSecretValue",
            resource="arn:aws:secretsmanager:us-east-1:123456789012:secret:production-db-password",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.SECRET,
        )
        decision = strict_service.authorize(request)
        # With strict thresholds, this should not be a simple ALLOW
        assert decision.decision in (Decision.DENY, Decision.STEP_UP, Decision.REVIEW)

    def test_create_login_profile_denied(self, service: AuthorizationService) -> None:
        """Creating login profiles (console access) is high risk."""
        request = AuthorizationRequest.create(
            agent_id="backdoor-agent",
            agent_name="login-creator",
            principal="attacker@evil.com",
            action="iam:CreateLoginProfile",
            resource="arn:aws:iam::123456789012:user/backdoor",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.SECRET,
        )
        decision = service.authorize(request)
        # Production fail-closed should deny or require step-up for unknown/unmatched high-risk actions
        assert decision.decision in (Decision.DENY, Decision.STEP_UP)


# =============================================================================
# Test: Cross-Account Access
# =============================================================================


class TestCrossAccountAccess:
    """Tests that cross-account access is properly controlled."""

    def test_assume_role_external_account_controlled(self, strict_service: AuthorizationService) -> None:
        """Assuming role in external account is flagged."""
        request = AuthorizationRequest.create(
            agent_id="lateral-agent",
            agent_name="cross-account-agent",
            principal="user@corp.com",
            action="sts:AssumeRole",
            resource="arn:aws:iam::999999999999:role/external-admin",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.SECRET,
        )
        decision = strict_service.authorize(request)
        assert decision.decision in (Decision.DENY, Decision.STEP_UP, Decision.REVIEW)

    def test_cross_account_s3_access_production(self, service: AuthorizationService) -> None:
        """Cross-account S3 bucket access in production is fail-closed."""
        request = AuthorizationRequest.create(
            agent_id="exfil-agent",
            agent_name="data-copier",
            principal="user@corp.com",
            action="s3:PutObject",
            resource="arn:aws:s3:::external-account-bucket/exfiltrated-data",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.SECRET,
        )
        decision = service.authorize(request)
        # Fail-closed production should deny unrecognized actions
        assert decision.decision == Decision.DENY


# =============================================================================
# Test: Destructive Actions
# =============================================================================


class TestDestructiveActions:
    """Tests that destructive actions are blocked in production."""

    def test_delete_cloudtrail_denied(self, service: AuthorizationService) -> None:
        """Deleting CloudTrail is denied."""
        request = AuthorizationRequest.create(
            agent_id="cover-tracks-agent",
            agent_name="trail-deleter",
            principal="attacker@evil.com",
            action="cloudtrail:DeleteTrail",
            resource="arn:aws:cloudtrail:us-east-1:123456789012:trail/production-audit",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.REGULATED,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY

    def test_stop_logging_denied(self, service: AuthorizationService) -> None:
        """Stopping CloudTrail logging is denied."""
        request = AuthorizationRequest.create(
            agent_id="evasion-agent",
            agent_name="log-stopper",
            principal="insider@corp.com",
            action="cloudtrail:StopLogging",
            resource="arn:aws:cloudtrail:us-east-1:123456789012:trail/main",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY

    def test_kms_key_deletion_denied(self, service: AuthorizationService) -> None:
        """Scheduling KMS key deletion is denied in production."""
        request = AuthorizationRequest.create(
            agent_id="ransom-agent",
            agent_name="key-destroyer",
            principal="attacker@evil.com",
            action="kms:ScheduleKeyDeletion",
            resource="arn:aws:kms:us-east-1:123456789012:key/master-encryption-key",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.SECRET,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY

    def test_guardduty_disable_denied(self, service: AuthorizationService) -> None:
        """Disabling GuardDuty is denied."""
        request = AuthorizationRequest.create(
            agent_id="evasion-agent",
            agent_name="guardduty-disabler",
            principal="compromised@corp.com",
            action="guardduty:DeleteDetector",
            resource="arn:aws:guardduty:us-east-1:123456789012:detector/main",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY


# =============================================================================
# Test: Confused Deputy
# =============================================================================


class TestConfusedDeputy:
    """Tests for confused deputy attack scenarios."""

    def test_agent_acting_on_wrong_resource(self, service: AuthorizationService) -> None:
        """Agent accessing resources outside its scope is denied."""
        request = AuthorizationRequest.create(
            agent_id="invoice-agent",
            agent_name="invoice-processor",
            principal="workflow@corp.com",
            action="iam:PassRole",
            resource="arn:aws:iam::123456789012:role/unrelated-admin-role",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY

    def test_agent_assuming_more_privileged_role(self, strict_service: AuthorizationService) -> None:
        """Agent trying to assume a more privileged role is controlled."""
        request = AuthorizationRequest.create(
            agent_id="low-priv-agent",
            agent_name="data-reader",
            principal="service@corp.com",
            action="sts:AssumeRole",
            resource="arn:aws:iam::123456789012:role/admin-full-access",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.SECRET,
        )
        decision = strict_service.authorize(request)
        assert decision.decision in (Decision.DENY, Decision.STEP_UP)


# =============================================================================
# Test: Data Exfiltration
# =============================================================================


class TestDataExfiltration:
    """Tests that data exfiltration attempts are blocked."""

    def test_s3_public_bucket_policy_denied(self, service: AuthorizationService) -> None:
        """Making bucket public via PutBucketPolicy in production is denied."""
        request = AuthorizationRequest.create(
            agent_id="exfil-agent",
            agent_name="bucket-exposer",
            principal="insider@corp.com",
            action="s3:PutBucketPolicy",
            resource="arn:aws:s3:::confidential-data-bucket",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.SECRET,
        )
        decision = service.authorize(request)
        # Fail-closed in production for unrecognized S3 admin actions
        assert decision.decision in (Decision.DENY, Decision.STEP_UP)

    def test_bulk_s3_copy_flagged(self, strict_service: AuthorizationService) -> None:
        """Bulk data copy operations are flagged for review."""
        request = AuthorizationRequest.create(
            agent_id="data-mover",
            agent_name="bulk-copier",
            principal="user@corp.com",
            action="s3:GetObject",
            resource="arn:aws:s3:::production-database-exports/*",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.REGULATED,
        )
        decision = strict_service.authorize(request)
        # Strict thresholds + production + regulated = should not be simple allow
        assert decision.decision in (Decision.DENY, Decision.STEP_UP, Decision.REVIEW)


# =============================================================================
# Test: Policy Bypass Attempts
# =============================================================================


class TestPolicyBypass:
    """Tests that policy bypass attempts are caught."""

    def test_put_role_policy_denied(self, service: AuthorizationService) -> None:
        """Inline policy modification in production is denied."""
        request = AuthorizationRequest.create(
            agent_id="bypass-agent",
            agent_name="policy-modifier",
            principal="attacker@evil.com",
            action="iam:PutRolePolicy",
            resource="arn:aws:iam::123456789012:role/any-role",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY

    def test_permission_boundary_modification_controlled(self, strict_service: AuthorizationService) -> None:
        """Modifying permission boundaries is high risk."""
        request = AuthorizationRequest.create(
            agent_id="boundary-breaker",
            agent_name="boundary-modifier",
            principal="insider@corp.com",
            action="iam:PutRolePermissionsBoundary",
            resource="arn:aws:iam::123456789012:role/restricted-agent-role",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.SECRET,
        )
        decision = strict_service.authorize(request)
        assert decision.decision in (Decision.DENY, Decision.STEP_UP)

    def test_config_recorder_stop_denied(self, service: AuthorizationService) -> None:
        """Stopping Config Recorder is denied."""
        request = AuthorizationRequest.create(
            agent_id="config-stopper",
            agent_name="config-agent",
            principal="insider@corp.com",
            action="config:StopConfigurationRecorder",
            resource="*",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.INTERNAL,
        )
        decision = service.authorize(request)
        assert decision.decision == Decision.DENY

    def test_organization_leave_denied(self, service: AuthorizationService) -> None:
        """Leaving the organization is blocked in production."""
        request = AuthorizationRequest.create(
            agent_id="org-agent",
            agent_name="org-leaver",
            principal="rogue@corp.com",
            action="organizations:LeaveOrganization",
            resource="*",
            environment=Environment.PRODUCTION,
            data_classification=DataClassification.SECRET,
        )
        decision = service.authorize(request)
        # Fail-closed catches this
        assert decision.decision in (Decision.DENY, Decision.STEP_UP)
