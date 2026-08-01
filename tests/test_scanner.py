from aws_agent_identity_guard import scan_policy_document


def test_flags_wildcard_agent_permissions():
    findings = scan_policy_document({
        "Statement": [{
            "Effect": "Allow",
            "Action": ["bedrock:*", "lambda:InvokeFunction", "iam:PassRole"],
            "Resource": "*",
        }]
    })
    rule_ids = {finding.rule_id for finding in findings}
    assert {"AIG002", "AIG003", "AIG004", "AIG006"}.issubset(rule_ids)


def test_sensitive_data_without_session_tag_is_medium():
    findings = scan_policy_document({
        "Statement": [{
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "arn:aws:secretsmanager:us-east-1:111122223333:secret:agent/db",
        }]
    })
    assert [(f.rule_id, f.severity) for f in findings] == [("AIG007", "medium")]


def test_scoped_tool_policy_passes_high_risk_checks():
    findings = scan_policy_document({
        "Statement": [{
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": "arn:aws:lambda:us-east-1:111122223333:function:approved-agent-tool",
            "Condition": {"StringEquals": {"aws:PrincipalTag/agent-owner": "security"}},
        }]
    })
    assert not [f for f in findings if f.severity in {"high", "critical"}]