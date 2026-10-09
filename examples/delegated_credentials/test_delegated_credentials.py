"""
examples/delegated_credentials/test_delegated_credentials.py
==============================================================================
MOCKED DEMO TESTS  ·  Gap 3

>>> ALL AWS CALLS HERE ARE MOCKED BY moto (@mock_aws). NO REAL AWS. <<<

Proves three properties of the delegated-credentials pattern:

  (a) valid OIDC subject + correct ExternalId -> scoped temp creds w/ expiry
  (b) missing / wrong ExternalId -> AccessDenied (confused deputy prevented)
  (c) creds are short-lived (DurationSeconds is respected in the Expiration)

Run:
    # from repo root, using the demo venv that has moto+boto3
    .venv-run\\Scripts\\python.exe -m pytest \\
        examples/delegated_credentials/test_delegated_credentials.py -v
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

# moto/boto3 are required; skip cleanly (labelled UNVERIFIED) if unavailable.
boto3 = pytest.importorskip("boto3", reason="boto3 required for MOCKED demo")
moto = pytest.importorskip("moto", reason="moto required for MOCKED demo")

from moto import mock_aws  # type: ignore[import]  # noqa: E402

# Import the sibling demo module by path so this works regardless of packaging.
_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "delegated_credentials_demo", _HERE / "delegated_credentials.py"
)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _mod
_spec.loader.exec_module(_mod)

assume_role_for_agent = _mod.assume_role_for_agent
build_web_identity_trust_policy = _mod.build_web_identity_trust_policy
ScopedCredentials = _mod.ScopedCredentials
ConfusedDeputyError = _mod.ConfusedDeputyError


# ---------------------------------------------------------------------------
# Fixtures / constants
# ---------------------------------------------------------------------------
OIDC_PROVIDER = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
ROLE_ARN = "arn:aws:iam::123456789012:role/agent-delegated-role"
ALLOWED_SUBJECT = "repo:poojakira/aws-agent-identity-guard:ref:refs/heads/main"
EXTERNAL_ID = "agent-tenant-7f3a-external-id"
MOCK_TOKEN = "mock.oidc.jwt.header.payload.sig"  # NOT a real JWT — MOCKED demo.


@pytest.fixture(autouse=True)
def _fake_aws_env(monkeypatch):
    """Ensure no real AWS creds leak in; moto ignores these but be explicit."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# (a) valid OIDC subject + correct ExternalId -> scoped temp creds with expiry
# ---------------------------------------------------------------------------
@mock_aws
def test_valid_oidc_and_external_id_returns_scoped_temp_creds():
    creds = assume_role_for_agent(
        role_arn=ROLE_ARN,
        web_identity_token=MOCK_TOKEN,
        session_name="agent-session",
        duration_seconds=900,
        provided_external_id=EXTERNAL_ID,
        expected_external_id=EXTERNAL_ID,
    )

    assert isinstance(creds, ScopedCredentials)
    # Temporary creds always carry a session token; static keys do not.
    assert creds.session_token
    assert creds.is_short_lived is True
    assert creds.access_key_id
    assert creds.secret_access_key
    # An expiry MUST be present — this is what makes them short-lived.
    assert isinstance(creds.expiration, datetime)
    # AssumedRoleUser arn should reflect the assumed role session.
    assert "assumed-role" in creds.assumed_role_arn or ROLE_ARN in creds.assumed_role_arn


# ---------------------------------------------------------------------------
# (b) missing / wrong ExternalId -> AccessDenied (confused deputy prevented)
# ---------------------------------------------------------------------------
@mock_aws
def test_wrong_external_id_denied_confused_deputy_prevented():
    with pytest.raises(ConfusedDeputyError) as excinfo:
        assume_role_for_agent(
            role_arn=ROLE_ARN,
            web_identity_token=MOCK_TOKEN,
            session_name="agent-session",
            duration_seconds=900,
            provided_external_id="attacker-guessed-id",
            expected_external_id=EXTERNAL_ID,
        )
    assert "AccessDenied" in str(excinfo.value)


@mock_aws
def test_missing_external_id_denied_confused_deputy_prevented():
    with pytest.raises(ConfusedDeputyError) as excinfo:
        assume_role_for_agent(
            role_arn=ROLE_ARN,
            web_identity_token=MOCK_TOKEN,
            session_name="agent-session",
            duration_seconds=900,
            provided_external_id=None,
            expected_external_id=EXTERNAL_ID,
        )
    assert "AccessDenied" in str(excinfo.value)


# ---------------------------------------------------------------------------
# (c) creds are short-lived (DurationSeconds respected in Expiration)
# ---------------------------------------------------------------------------
@mock_aws
def test_credentials_are_short_lived_duration_respected():
    duration = 900  # 15 minutes — the least-privilege short lifetime.
    before = datetime.now(timezone.utc)

    creds = assume_role_for_agent(
        role_arn=ROLE_ARN,
        web_identity_token=MOCK_TOKEN,
        session_name="agent-session",
        duration_seconds=duration,
        provided_external_id=EXTERNAL_ID,
        expected_external_id=EXTERNAL_ID,
    )

    exp = creds.expiration
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)

    lifetime = (exp - before).total_seconds()
    # Expiry must be in the future and within a short window of the requested
    # duration (allow slack for mock clock + request time).
    assert lifetime > 0, "credentials must expire in the future"
    assert lifetime <= duration + 60, (
        f"credentials lifetime {lifetime}s exceeds requested short duration "
        f"{duration}s (+slack) — not short-lived"
    )


@mock_aws
def test_longer_duration_produces_later_expiry_than_short_duration():
    """Sanity: a larger DurationSeconds yields a later expiry (monotonic)."""
    short = assume_role_for_agent(
        role_arn=ROLE_ARN,
        web_identity_token=MOCK_TOKEN,
        session_name="s-short",
        duration_seconds=900,
        provided_external_id=EXTERNAL_ID,
        expected_external_id=EXTERNAL_ID,
    )
    longer = assume_role_for_agent(
        role_arn=ROLE_ARN,
        web_identity_token=MOCK_TOKEN,
        session_name="s-long",
        duration_seconds=3600,
        provided_external_id=EXTERNAL_ID,
        expected_external_id=EXTERNAL_ID,
    )

    def _aware(dt):
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    assert _aware(longer.expiration) > _aware(short.expiration)


# ---------------------------------------------------------------------------
# Supporting: the trust policy carries the ExternalId condition + OIDC pins.
# ---------------------------------------------------------------------------
def test_trust_policy_pins_oidc_subject_audience_and_external_id():
    policy = build_web_identity_trust_policy(
        oidc_provider_arn=OIDC_PROVIDER,
        oidc_audience="sts.amazonaws.com",
        allowed_subject=ALLOWED_SUBJECT,
        external_id=EXTERNAL_ID,
    )
    stmt = policy["Statement"][0]
    assert stmt["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert stmt["Principal"]["Federated"] == OIDC_PROVIDER
    cond = stmt["Condition"]["StringEquals"]
    host = "token.actions.githubusercontent.com"
    assert cond[f"{host}:aud"] == "sts.amazonaws.com"
    assert cond[f"{host}:sub"] == ALLOWED_SUBJECT
    # The confused-deputy control:
    assert cond["sts:ExternalId"] == EXTERNAL_ID
