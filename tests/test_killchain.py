"""
Tests for policy-level combination rules (AIG019-AIG021).

These rules detect combinations across a whole policy that per-statement linters
can miss: credential access, metadata enumeration, and lateral movement.
"""

from aws_agent_identity_guard import scan_policy_document


class TestKillChainCombinations:
    def test_harvest_plus_lateral_is_aig019_critical(self):
        """Credential read plus assume-role is a high-risk combination."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "arn:aws:secretsmanager:us-east-1:111:secret:agent/*",
                    "Condition": {"StringEquals": {"aws:PrincipalTag/tenant": "x"}},
                },
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::111:role/worker",
                    "Condition": {"StringLike": {"aws:RequestTag/agent-session-id": "*"}},
                },
            ]
        }
        findings = scan_policy_document(policy)
        aig019 = [f for f in findings if f.rule_id == "AIG019"]
        assert aig019, "harvest + lateral combination must trigger AIG019"
        assert aig019[0].severity == "critical"

    def test_harvest_plus_metadata_is_aig020(self):
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "ssm:GetParameter", "Resource": "*"},
                {"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"},
            ]
        }
        findings = scan_policy_document(policy)
        assert any(f.rule_id == "AIG020" for f in findings)

    def test_full_chain_is_aig021(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetSecretValue", "eks:DescribeCluster"],
                    "Resource": "*",
                },
                {"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"},
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
            ]
        }
        findings = scan_policy_document(policy)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG021" in rule_ids, "complete chain must trigger AIG021"

    def test_harvest_only_does_not_trigger_combination(self):
        """Reading secrets alone is not a kill chain — no combination rule fires."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "arn:aws:secretsmanager:us-east-1:111:secret:agent/db",
                    "Condition": {"StringEquals": {"aws:PrincipalTag/tenant": "x"}},
                }
            ]
        }
        findings = scan_policy_document(policy)
        combo = [f for f in findings if f.rule_id in ("AIG019", "AIG020", "AIG021")]
        assert combo == [], "harvest alone must not trigger a combination rule"

    def test_lateral_only_does_not_trigger_combination(self):
        """Assume-role alone (no credential harvest) is not the chain."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::111:role/worker",
                    "Condition": {"StringLike": {"aws:RequestTag/agent-session-id": "*"}},
                }
            ]
        }
        findings = scan_policy_document(policy)
        combo = [f for f in findings if f.rule_id in ("AIG019", "AIG020", "AIG021")]
        assert combo == [], "lateral alone must not trigger a combination rule"

    def test_wildcard_action_uses_aig002_not_combination_rules(self):
        """Wildcard action is already covered by AIG002 and should not inflate combos."""
        policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        findings = scan_policy_document(policy)
        rule_ids = {f.rule_id for f in findings}
        assert "AIG002" in rule_ids
        assert not {"AIG019", "AIG020", "AIG021"} & rule_ids
