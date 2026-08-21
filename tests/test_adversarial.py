"""
tests/test_adversarial.py
--------------------------
Adversarial test suite for the AWS Agent Identity Guard system.

Simulates realistic attack scenarios and verifies that the system detects
and blocks them. Covers privilege escalation, credential theft, cross-account
access, destructive actions, confused deputy, data exfiltration, and policy
bypass attempts.
"""

from __future__ import annotations

from aws_agent_identity_guard.attack_paths import AttackPathAnalyzer
from aws_agent_identity_guard.authorization import (
    AuthorizationConfig,
    AuthorizationEngine,
    AuthorizationMode,
)
from aws_agent_identity_guard.escalation_engine import EscalationDetector
from aws_agent_identity_guard.models import (
    AgentIdentity,
    AgentType,
    AuthorizationDecisionType,
    DataClassification,
    EffectiveEffect,
    EffectivePermission,
    Environment,
    TransactionRequest,
)
from aws_agent_identity_guard.policy_engine import PolicyEngine
from aws_agent_identity_guard.risk_engine import RiskEngine

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _agent(
    agent_id: str,
    name: str,
    env: Environment = Environment.PRODUCTION,
    classification: DataClassification = DataClassification.CONFIDENTIAL,
) -> AgentIdentity:
    """Create an agent with given properties."""
    return AgentIdentity(
        agent_id=agent_id,
        name=name,
        agent_type=AgentType.BEDROCK,
        owner="test-owner",
        environment=env,
        data_classification=classification,
    )


def _perms(actions: list[str]) -> list[EffectivePermission]:
    """Create ALLOWED effective permissions for actions."""
    return [
        EffectivePermission(action=a, resource="*", effective_effect=EffectiveEffect.ALLOWED)
        for a in actions
    ]


def _authz_engine_with_deny_policy() -> AuthorizationEngine:
    """Create an authorization engine with a comprehensive deny policy."""
    policy_engine = PolicyEngine()
    policy_engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: deny-all-iam-mutate
    effect: deny
    actions: ['iam:*']
    resources: ['*']
    priority: 100
  - name: deny-secrets-prod
    effect: deny
    actions: ['secretsmanager:GetSecretValue']
    resources: ['*']
    environments: ['PRODUCTION']
    priority: 90
  - name: deny-destructive-s3
    effect: deny
    actions: ['s3:DeleteBucket', 's3:DeleteObject']
    resources: ['*']
    priority: 80
  - name: deny-cross-account-assume
    effect: deny
    actions: ['sts:AssumeRole']
    resources: ['*']
    priority: 95
  - name: deny-ec2-terminate
    effect: deny
    actions: ['ec2:TerminateInstances']
    resources: ['*']
    priority: 80
  - name: deny-rds-delete
    effect: deny
    actions: ['rds:DeleteDBInstance', 'rds:DeleteDBCluster']
    resources: ['*']
    priority: 80
""")
    config = AuthorizationConfig(
        mode=AuthorizationMode.FAIL_CLOSED,
        deny_threshold=90.0,
    )
    engine = AuthorizationEngine(
        config=config,
        risk_engine=RiskEngine(),
        policy_engine=policy_engine,
    )
    return engine


# ─── Privilege Escalation Scenarios ──────────────────────────────────────────


class TestPrivilegeEscalation:
    """Test that privilege escalation attempts are detected and blocked."""

    def test_create_policy_version_blocked(self):
        """Agent attempting iam:CreatePolicyVersion is DENIED."""
        engine = _authz_engine_with_deny_policy()
        agent = _agent("esc-1", "EscalationAgent1")
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="esc-1",
            principal="role",
            tool="iam-tool",
            action="iam:CreatePolicyVersion",
            resource="*",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_attach_admin_policy_blocked(self):
        """Agent attempting iam:AttachRolePolicy is DENIED."""
        engine = _authz_engine_with_deny_policy()
        agent = _agent("esc-2", "EscalationAgent2")
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="esc-2",
            principal="role",
            tool="iam-tool",
            action="iam:AttachRolePolicy",
            resource="*",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_passrole_to_lambda_blocked(self):
        """Agent attempting iam:PassRole is DENIED."""
        engine = _authz_engine_with_deny_policy()
        agent = _agent("esc-3", "EscalationAgent3")
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="esc-3",
            principal="role",
            tool="lambda-tool",
            action="iam:PassRole",
            resource="*",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_update_trust_policy_blocked(self):
        """Agent attempting iam:UpdateAssumeRolePolicy is DENIED."""
        engine = _authz_engine_with_deny_policy()
        agent = _agent("esc-4", "EscalationAgent4")
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="esc-4",
            principal="role",
            tool="iam-tool",
            action="iam:UpdateAssumeRolePolicy",
            resource="*",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_create_user_blocked(self):
        """Agent attempting iam:CreateUser is DENIED."""
        engine = _authz_engine_with_deny_policy()
        agent = _agent("esc-5", "EscalationAgent5")
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="esc-5",
            principal="role",
            tool="iam-tool",
            action="iam:CreateUser",
            resource="*",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_escalation_detector_finds_all_patterns(self):
        """Escalation detector catches combined dangerous permissions."""
        detector = EscalationDetector()
        agent = _agent("esc-full", "FullEscAgent")
        perms = _perms(
            [
                "iam:CreatePolicyVersion",
                "iam:AttachRolePolicy",
                "iam:PassRole",
                "lambda:CreateFunction",
                "iam:UpdateAssumeRolePolicy",
            ]
        )
        results = detector.detect(agent, perms)
        assert len(results) >= 4


# ─── Credential Theft Scenarios ──────────────────────────────────────────────


class TestCredentialTheft:
    """Test that credential theft attempts are detected and blocked."""

    def test_get_secret_value_production_blocked(self):
        """Secrets access in production is DENIED."""
        engine = _authz_engine_with_deny_policy()
        agent = _agent("cred-1", "CredTheftAgent1", env=Environment.PRODUCTION)
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="cred-1",
            principal="role",
            tool="secrets-tool",
            action="secretsmanager:GetSecretValue",
            resource="arn:aws:secretsmanager:us-east-1:123456789012:secret:api-key",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_ssm_get_parameters_detected(self):
        """SSM parameter access is flagged by attack path analyzer."""
        analyzer = AttackPathAnalyzer()
        agent = _agent("cred-2", "CredTheftAgent2")
        perms = _perms(["ssm:GetParameter", "ssm:GetParametersByPath"])
        paths = analyzer.analyze(agent, perms)
        assert len(paths) > 0

    def test_kms_decrypt_detected(self):
        """KMS Decrypt with secrets access is flagged."""
        analyzer = AttackPathAnalyzer()
        agent = _agent("cred-3", "CredTheftAgent3")
        perms = _perms(["kms:Decrypt", "secretsmanager:GetSecretValue"])
        paths = analyzer.analyze(agent, perms)
        assert len(paths) > 0

    def test_create_access_key_escalation_detected(self):
        """iam:CreateAccessKey is detected as escalation."""
        detector = EscalationDetector()
        agent = _agent("cred-4", "CredTheftAgent4")
        perms = _perms(["iam:CreateAccessKey"])
        results = detector.detect(agent, perms)
        # CreateAccessKey is part of credential-related patterns
        assert len(results) > 0

    def test_multiple_credential_theft_vectors(self):
        """Combined credential access vectors all get flagged."""
        analyzer = AttackPathAnalyzer()
        agent = _agent("cred-5", "CredTheftAgent5")
        perms = _perms(
            [
                "secretsmanager:GetSecretValue",
                "secretsmanager:ListSecrets",
                "ssm:GetParameter",
                "kms:Decrypt",
            ]
        )
        paths = analyzer.analyze(agent, perms)
        assert len(paths) >= 2


# ─── Cross-Account Access Scenarios ──────────────────────────────────────────


class TestCrossAccountAccess:
    """Test detection of cross-account access attempts."""

    def test_assume_role_cross_account_blocked(self):
        """sts:AssumeRole is DENIED by policy."""
        engine = _authz_engine_with_deny_policy()
        agent = _agent("xacct-1", "CrossAccountAgent1")
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="xacct-1",
            principal="role",
            tool="cross-tool",
            action="sts:AssumeRole",
            resource="arn:aws:iam::999888777666:role/AdminRole",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_cross_account_role_chaining_detected(self):
        """Role chaining with wildcard is detected as attack path."""
        analyzer = AttackPathAnalyzer()
        agent = _agent("xacct-2", "CrossAccountAgent2")
        perms = _perms(["sts:AssumeRole", "sts:AssumeRoleWithSAML"])
        paths = analyzer.analyze(agent, perms)
        assert len(paths) >= 1
        # Should detect cross-account patterns
        assert any(p.composite_score > 50 for p in paths)

    def test_federation_token_detected(self):
        """sts:GetFederationToken is flagged in risk scoring."""
        engine = RiskEngine()
        agent = _agent("xacct-3", "CrossAccountAgent3")
        perms = _perms(["sts:GetFederationToken", "sts:AssumeRole"])
        score = engine.score_agent(agent, perms, [])
        assert score.privilege > 0


# ─── Destructive Action Scenarios ────────────────────────────────────────────


class TestDestructiveActions:
    """Test that destructive actions are blocked."""

    def test_delete_s3_bucket_blocked(self):
        """s3:DeleteBucket is DENIED."""
        engine = _authz_engine_with_deny_policy()
        agent = _agent("dest-1", "DestructiveAgent1")
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="dest-1",
            principal="role",
            tool="s3-tool",
            action="s3:DeleteBucket",
            resource="arn:aws:s3:::critical-bucket",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_terminate_instances_blocked(self):
        """ec2:TerminateInstances is DENIED."""
        engine = _authz_engine_with_deny_policy()
        agent = _agent("dest-2", "DestructiveAgent2")
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="dest-2",
            principal="role",
            tool="ec2-tool",
            action="ec2:TerminateInstances",
            resource="*",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_delete_db_instance_blocked(self):
        """rds:DeleteDBInstance is DENIED."""
        engine = _authz_engine_with_deny_policy()
        agent = _agent("dest-3", "DestructiveAgent3")
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="dest-3",
            principal="role",
            tool="rds-tool",
            action="rds:DeleteDBInstance",
            resource="*",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY


# ─── Confused Deputy Scenarios ───────────────────────────────────────────────


class TestConfusedDeputy:
    """Test detection of confused deputy exploitation attempts."""

    def test_lambda_invoke_with_passrole_detected(self):
        """Agent invoking Lambda + PassRole creates confused deputy risk."""
        detector = EscalationDetector()
        agent = _agent("deputy-1", "ConfusedDeputy1")
        perms = _perms(["lambda:InvokeFunction", "iam:PassRole", "lambda:CreateFunction"])
        results = detector.detect(agent, perms)
        assert len(results) > 0

    def test_cross_service_exploitation_scored(self):
        """Cross-service exploitation raises risk score."""
        engine = RiskEngine()
        agent = _agent("deputy-2", "ConfusedDeputy2")
        perms = _perms(
            [
                "lambda:InvokeFunction",
                "iam:PassRole",
                "ecs:RunTask",
                "sagemaker:CreateNotebookInstance",
            ]
        )
        score = engine.score_agent(agent, perms, [])
        assert score.lateral_movement > 0
        assert score.privilege > 0

    def test_bedrock_agent_passrole_detected(self):
        """bedrock:CreateAgent + iam:PassRole is detected."""
        detector = EscalationDetector()
        agent = _agent("deputy-3", "ConfusedDeputy3")
        perms = _perms(["bedrock:CreateAgent", "iam:PassRole"])
        results = detector.detect(agent, perms)
        techniques = [r.technique for r in results]
        assert any("Bedrock" in t for t in techniques)


# ─── Data Exfiltration Scenarios ─────────────────────────────────────────────


class TestDataExfiltration:
    """Test detection of data exfiltration attempts."""

    def test_s3_wildcard_read_flagged(self):
        """S3 read with wildcard resource raises data exposure risk."""
        engine = RiskEngine()
        agent = _agent("exfil-1", "ExfilAgent1")
        perms = _perms(["s3:GetObject", "s3:ListBucket"])
        score = engine.score_agent(agent, perms, [])
        assert score.data_exposure > 0

    def test_dynamodb_scan_flagged(self):
        """DynamoDB Scan raises data exposure risk."""
        engine = RiskEngine()
        agent = _agent("exfil-2", "ExfilAgent2")
        perms = _perms(["dynamodb:Scan", "dynamodb:Query"])
        score = engine.score_agent(agent, perms, [])
        assert score.data_exposure > 0

    def test_athena_query_flagged(self):
        """Athena query execution raises data exposure risk."""
        engine = RiskEngine()
        agent = _agent("exfil-3", "ExfilAgent3")
        perms = _perms(["athena:StartQueryExecution", "s3:GetObject"])
        score = engine.score_agent(agent, perms, [])
        assert score.data_exposure > 0

    def test_s3_public_access_flagged(self):
        """S3 public access modification raises data exposure risk."""
        engine = RiskEngine()
        agent = _agent("exfil-4", "ExfilAgent4")
        perms = _perms(["s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:PutObjectAcl"])
        score = engine.score_agent(agent, perms, [])
        assert score.data_exposure > 0

    def test_combined_exfiltration_vectors(self):
        """Multiple data access paths compound risk."""
        engine = RiskEngine()
        agent = _agent("exfil-5", "ExfilAgent5")
        perms = _perms(
            [
                "s3:GetObject",
                "s3:ListBucket",
                "dynamodb:Scan",
                "dynamodb:BatchGetItem",
                "athena:StartQueryExecution",
                "logs:GetLogEvents",
            ]
        )
        score = engine.score_agent(agent, perms, [])
        assert score.data_exposure >= 30

    def test_exfiltration_attack_paths_found(self):
        """Attack path analyzer finds exfiltration paths."""
        analyzer = AttackPathAnalyzer()
        agent = _agent("exfil-6", "ExfilAgent6")
        perms = _perms(["s3:GetObject", "s3:ListBucket", "s3:GetBucketPolicy"])
        paths = analyzer.analyze(agent, perms)
        assert len(paths) > 0


# ─── Policy Bypass Attempts ──────────────────────────────────────────────────


class TestPolicyBypass:
    """Test that policy bypass attempts are detected and blocked."""

    def test_wildcard_action_blocked_by_deny(self):
        """Wildcard iam action is blocked by deny-all-iam-mutate policy."""
        engine = _authz_engine_with_deny_policy()
        agent = _agent("bypass-1", "BypassAgent1")
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="bypass-1",
            principal="role",
            tool="tool",
            action="iam:PutRolePolicy",
            resource="*",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_unregistered_agent_denied(self):
        """Requests from unregistered agents are denied (fail-closed)."""
        engine = _authz_engine_with_deny_policy()
        request = TransactionRequest(
            agent_id="unknown-agent",
            principal="role",
            tool="tool",
            action="s3:GetObject",
            resource="*",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_escalation_via_service_wildcard_detected(self):
        """Service-level wildcard (iam:*) triggers escalation detection."""
        detector = EscalationDetector()
        agent = _agent("bypass-3", "BypassAgent3")
        perms = _perms(["iam:*"])
        results = detector.detect(agent, perms)
        # iam:* should match MANY escalation patterns
        assert len(results) >= 5

    def test_high_risk_score_overrides_no_explicit_deny(self):
        """Extremely high risk score triggers auto-deny even without explicit deny rule."""
        policy_engine = PolicyEngine()
        policy_engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: allow-all
    effect: allow
    actions: ['*']
    resources: ['*']
""")
        config = AuthorizationConfig(
            mode=AuthorizationMode.FAIL_CLOSED,
            deny_threshold=20.0,  # Very low threshold for test
        )
        engine = AuthorizationEngine(
            config=config,
            risk_engine=RiskEngine(),
            policy_engine=policy_engine,
        )
        agent = _agent(
            "bypass-4",
            "BypassAgent4",
            env=Environment.PRODUCTION,
            classification=DataClassification.SECRET,
        )
        engine.agent_registry.register(agent)
        # Dangerous action should score high enough to auto-deny
        request = TransactionRequest(
            agent_id="bypass-4",
            principal="role",
            tool="tool",
            action="iam:CreatePolicyVersion",
            resource="*",
            data_classification=DataClassification.SECRET,
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY

    def test_no_allow_rule_defaults_deny(self):
        """Without any allow rule, fail-closed denies all requests."""
        policy_engine = PolicyEngine()
        policy_engine.load_policies_from_string("""
version: '1.0'
policies:
  - name: step-up-only
    effect: step_up
    actions: ['secretsmanager:*']
    resources: ['*']
""")
        config = AuthorizationConfig(mode=AuthorizationMode.FAIL_CLOSED)
        engine = AuthorizationEngine(
            config=config,
            risk_engine=RiskEngine(),
            policy_engine=policy_engine,
        )
        agent = _agent("bypass-5", "BypassAgent5")
        engine.agent_registry.register(agent)
        request = TransactionRequest(
            agent_id="bypass-5",
            principal="role",
            tool="tool",
            action="s3:GetObject",
            resource="*",
        )
        decision = engine.authorize(request)
        assert decision.decision == AuthorizationDecisionType.DENY
