from aws_agent_identity_guard import scan_policy_document, scan_trust_policy
from aws_agent_identity_guard.scanner import Finding


def test_flags_wildcard_agent_permissions():
    findings = scan_policy_document(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["bedrock:*", "lambda:InvokeFunction", "iam:PassRole"],
                    "Resource": "*",
                }
            ]
        }
    )
    rule_ids = {finding.rule_id for finding in findings}
    assert {"AIG002", "AIG003", "AIG004", "AIG006"}.issubset(rule_ids)


def test_sensitive_data_without_session_tag_is_medium():
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
    assert [(f.rule_id, f.severity) for f in findings] == [("AIG007", "medium")]


def test_scoped_tool_policy_passes_high_risk_checks():
    findings = scan_policy_document(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": "arn:aws:lambda:us-east-1:111122223333:function:approved-agent-tool",
                    "Condition": {"StringEquals": {"aws:PrincipalTag/agent-owner": "security"}},
                }
            ]
        }
    )
    assert not [f for f in findings if f.severity in {"high", "critical"}]


# ---------------------------------------------------------------------------
# Trust-policy tests
# ---------------------------------------------------------------------------


def test_trust_policy_wildcard_principal_is_critical():
    """AIG-TP001: Principal '*' in a trust policy is CRITICAL."""
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
    rule_ids = {f.rule_id for f in findings}
    assert "AIG-TP001" in rule_ids
    critical = [f for f in findings if f.rule_id == "AIG-TP001"]
    assert critical[0].severity == "critical"


def test_trust_policy_cross_account_missing_external_id_is_high():
    """AIG-TP002: cross-account trust with no sts:ExternalId condition is HIGH."""
    findings = scan_trust_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::999988887777:root"
                    },
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    rule_ids = {f.rule_id for f in findings}
    assert "AIG-TP002" in rule_ids
    findings_tp002 = [f for f in findings if f.rule_id == "AIG-TP002"]
    assert findings_tp002[0].severity == "high"


def test_trust_policy_cross_account_missing_source_arn_is_high():
    """AIG-TP003: cross-account trust with no aws:SourceArn condition is HIGH."""
    findings = scan_trust_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::999988887777:root"
                    },
                    "Action": "sts:AssumeRole",
                    # Has ExternalId but no SourceArn
                    "Condition": {
                        "StringEquals": {"sts:ExternalId": "abc-123"}
                    },
                }
            ],
        }
    )
    rule_ids = {f.rule_id for f in findings}
    # TP002 should NOT fire (ExternalId is present), TP003 should fire
    assert "AIG-TP002" not in rule_ids
    assert "AIG-TP003" in rule_ids
    findings_tp003 = [f for f in findings if f.rule_id == "AIG-TP003"]
    assert findings_tp003[0].severity == "high"


def test_trust_policy_well_formed_cross_account_passes():
    """Cross-account trust with both ExternalId and aws:SourceArn should produce no TP findings."""
    findings = scan_trust_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::999988887777:root"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "unique-external-id-42",
                            "aws:SourceArn": "arn:aws:iam::999988887777:role/trusted-role",
                        }
                    },
                }
            ],
        }
    )
    tp_findings = [f for f in findings if f.rule_id.startswith("AIG-TP")]
    assert tp_findings == []


def test_trust_policy_malformed_input_raises_type_error():
    """scan_trust_policy must raise TypeError on non-dict input, not silently pass."""
    import pytest

    with pytest.raises(TypeError, match="trust policy document must be a dict"):
        scan_trust_policy("not a dict")  # type: ignore[arg-type]


def test_trust_policy_malformed_statement_list_is_skipped():
    """Non-dict entries in the Statement list must be skipped without error."""
    findings = scan_trust_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                "not a dict",
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole",
                },
            ],
        }
    )
    # The string entry should be silently skipped; the wildcard entry should fire
    assert any(f.rule_id == "AIG-TP001" for f in findings)
