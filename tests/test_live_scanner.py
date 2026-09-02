"""
tests/test_live_scanner.py
──────────────────────────────────────────────────────────────────────────────
Tests for the Boto3-based live AWS IAM scanner using moto.

These tests spin up a mocked AWS account (no real AWS calls),
create real IAM resources, and verify the scanner finds expected issues.

Run with:
    pip install 'aws-agent-identity-guard[dev]'
    pytest tests/test_live_scanner.py -v
"""

from __future__ import annotations

import json

import pytest

boto3 = pytest.importorskip("boto3", reason="boto3 required for live scanner tests")
moto = pytest.importorskip("moto", reason="moto required for live scanner tests")

from moto import mock_aws  # type: ignore[import]  # noqa: E402

from aws_agent_identity_guard.live_scanner import LiveAccountScanner  # noqa: E402


def _session():
    import boto3 as _b3

    return _b3.Session(
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
    )


def _trust(principal: str | dict) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}],
        }
    )


def _policy(actions: list[str], resources: list[str]) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resources}],
        }
    )


@mock_aws
def test_live_scan_wildcard_action_is_critical():
    """Role with Action:* must produce CRITICAL AIG002."""
    sess = _session()
    iam = sess.client("iam")
    iam.create_role(
        RoleName="wildcard-role",
        AssumeRolePolicyDocument=_trust({"Service": "bedrock.amazonaws.com"}),
    )
    iam.put_role_policy(
        RoleName="wildcard-role", PolicyName="too-broad", PolicyDocument=_policy(["*"], ["*"])
    )

    report = LiveAccountScanner(session=sess).scan_account()
    rule_ids = {f["rule_id"] for f in report.findings}
    assert "AIG002" in rule_ids, f"Expected AIG002, got {rule_ids}"
    assert report.summary["critical"] >= 1


@mock_aws
def test_live_scan_wildcard_principal_is_critical():
    """Trust policy with Principal:* must produce CRITICAL AIG-TP001."""
    sess = _session()
    sess.client("iam").create_role(RoleName="open-trust", AssumeRolePolicyDocument=_trust("*"))

    report = LiveAccountScanner(session=sess).scan_account()
    assert "AIG-TP001" in {f["rule_id"] for f in report.findings}


@mock_aws
def test_live_scan_cross_account_missing_external_id():
    """Cross-account trust without ExternalId must produce HIGH AIG-TP002."""
    sess = _session()
    trust_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    sess.client("iam").create_role(
        RoleName="cross-account-role", AssumeRolePolicyDocument=trust_doc
    )

    report = LiveAccountScanner(session=sess).scan_account()
    assert "AIG-TP002" in {f["rule_id"] for f in report.findings}


@mock_aws
def test_live_scan_passrole_without_condition():
    """iam:PassRole without iam:PassedToService must produce CRITICAL AIG004."""
    sess = _session()
    iam = sess.client("iam")
    iam.create_role(
        RoleName="passrole-role",
        AssumeRolePolicyDocument=_trust({"Service": "lambda.amazonaws.com"}),
    )
    iam.put_role_policy(
        RoleName="passrole-role",
        PolicyName="passrole",
        PolicyDocument=_policy(["iam:PassRole"], ["*"]),
    )

    report = LiveAccountScanner(session=sess).scan_account()
    assert "AIG004" in {f["rule_id"] for f in report.findings}


@mock_aws
def test_live_scan_clean_role_no_high_critical():
    """Well-scoped role with narrow s3:GetObject must produce zero high/critical findings."""
    sess = _session()
    iam = sess.client("iam")
    iam.create_role(
        RoleName="clean-role", AssumeRolePolicyDocument=_trust({"Service": "bedrock.amazonaws.com"})
    )
    iam.put_role_policy(
        RoleName="clean-role",
        PolicyName="read-only",
        PolicyDocument=_policy(["s3:GetObject"], ["arn:aws:s3:::my-bucket/agent-data/*"]),
    )

    report = LiveAccountScanner(session=sess).scan_account()
    bad = [
        f
        for f in report.findings
        if f.get("resource_name") == "clean-role" and f["severity"] in ("high", "critical")
    ]
    assert bad == [], f"Clean role should have no high/critical findings, got: {bad}"


@mock_aws
def test_scan_role_by_name_returns_only_target_role():
    """scan_role_by_name() must return findings scoped to the named role only."""
    sess = _session()
    iam = sess.client("iam")
    iam.create_role(RoleName="target", AssumeRolePolicyDocument=_trust("*"))
    iam.create_role(
        RoleName="other", AssumeRolePolicyDocument=_trust({"Service": "lambda.amazonaws.com"})
    )

    findings = LiveAccountScanner(session=sess).scan_role_by_name("target")
    assert any(f["rule_id"] == "AIG-TP001" for f in findings)
    assert all(f["resource_name"] == "target" for f in findings)


@mock_aws
def test_scan_role_by_name_raises_on_missing():
    """scan_role_by_name() must raise ValueError for non-existent role."""
    sess = _session()
    with pytest.raises(ValueError, match="not found or access denied"):
        LiveAccountScanner(session=sess).scan_role_by_name("does-not-exist")


@mock_aws
def test_report_has_required_fields():
    """scan_account() report must contain all required top-level keys."""
    sess = _session()
    sess.client("iam").create_role(
        RoleName="any-role", AssumeRolePolicyDocument=_trust({"Service": "lambda.amazonaws.com"})
    )

    report = LiveAccountScanner(session=sess).scan_account().to_dict()
    required = {
        "account_id",
        "scan_timestamp",
        "region",
        "roles_scanned",
        "users_scanned",
        "findings",
        "summary",
        "roles",
        "errors",
    }
    missing = required - report.keys()
    assert not missing, f"Report missing keys: {missing}"
    assert report["roles_scanned"] >= 1
    assert "total" in report["summary"]


# ═══════════════════════════════════════════════════════════════════════════════
# AIG-PB001: permission-boundary presence check.
#
# WHY THESE LIVE (moto) TESTS AND NOT STATIC ONES:
# AIG-PB001 is NOT emitted by the static scanner (scan_policy_document). It is
# a *configuration*-level rule generated only in live-scan mode inside
# LiveAccountScanner._scan_role() - see
#   src/aws_agent_identity_guard/live_scanner.py:416-434
# It fires when a role has one or more high/critical findings AND the role has
# NO permissions boundary attached. A static policy dict carries no notion of a
# role-level permissions boundary, so the rule cannot be triggered on a static
# document. These tests therefore exercise the real trigger path via moto.
#
# NOTE ON THE moto CODE PATH:
# These tests use scan_role_by_name(), which reads the role via iam.get_role().
# moto populates PermissionsBoundary on get_role() but (as of moto 5.x) does NOT
# populate it on the list_roles() paginator used by the full-account scan. Using
# scan_role_by_name() lets the negative test faithfully assert the
# boundary-present branch - see live_scanner.py:309-338 for both code paths.
# ═══════════════════════════════════════════════════════════════════════════════


@mock_aws
def test_aig_pb001_fires_for_highrisk_role_without_boundary():
    """A role with high/critical findings and NO permissions boundary fires AIG-PB001."""
    sess = _session()
    iam = sess.client("iam")
    iam.create_role(
        RoleName="highrisk-no-boundary",
        AssumeRolePolicyDocument=_trust({"Service": "bedrock.amazonaws.com"}),
    )
    # Wildcard policy => guaranteed critical finding (AIG002), no boundary attached.
    iam.put_role_policy(
        RoleName="highrisk-no-boundary",
        PolicyName="too-broad",
        PolicyDocument=_policy(["*"], ["*"]),
    )

    findings = LiveAccountScanner(session=sess).scan_role_by_name("highrisk-no-boundary")
    pb_findings = [f for f in findings if f["rule_id"] == "AIG-PB001"]
    assert pb_findings, (
        f"Expected AIG-PB001 for high-risk role without boundary, "
        f"got rule IDs: {sorted({f['rule_id'] for f in findings})}"
    )
    assert pb_findings[0]["severity"] == "medium"
    assert pb_findings[0]["source"] == "configuration"


@mock_aws
def test_aig_pb001_does_not_fire_when_boundary_present():
    """The SAME high-risk policy with a permissions boundary attached must NOT fire AIG-PB001."""
    sess = _session()
    iam = sess.client("iam")

    # Create a managed policy to serve as the permissions boundary.
    boundary = iam.create_policy(
        PolicyName="agent-boundary",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["bedrock:InvokeModel"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    boundary_arn = boundary["Policy"]["Arn"]

    iam.create_role(
        RoleName="highrisk-with-boundary",
        AssumeRolePolicyDocument=_trust({"Service": "bedrock.amazonaws.com"}),
        PermissionsBoundary=boundary_arn,
    )
    # Identical wildcard policy => still has critical findings ...
    iam.put_role_policy(
        RoleName="highrisk-with-boundary",
        PolicyName="too-broad",
        PolicyDocument=_policy(["*"], ["*"]),
    )

    findings = LiveAccountScanner(session=sess).scan_role_by_name("highrisk-with-boundary")

    # Sanity: the role still has a high/critical finding (so the ONLY reason
    # AIG-PB001 would be suppressed is the presence of the boundary).
    high_crit = [f for f in findings if f["severity"] in ("high", "critical")]
    assert high_crit, "Expected the wildcard policy to still produce high/critical findings"

    pb_findings = [f for f in findings if f["rule_id"] == "AIG-PB001"]
    assert (
        not pb_findings
    ), f"AIG-PB001 must NOT fire when a permissions boundary is attached, got: {pb_findings}"
