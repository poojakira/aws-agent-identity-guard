"""
tests/test_condition_structural.py
───────────────────────────────────────────────────────────────────────────────
Regression tests for P0 fix: replace str(condition) substring matching with
structural condition key evaluation (_condition_has_key).

Each test documents the EXACT FALSE-NEGATIVE or FALSE-POSITIVE that the old
str(condition) approach produced, then asserts the new behaviour is correct.

Run with: pytest tests/test_condition_structural.py -v
"""

import pytest
from aws_agent_identity_guard import scan_policy_document, scan_trust_policy
from aws_agent_identity_guard.scanner import _condition_has_key, _condition_has_key_any


# ═══════════════════════════════════════════════════════════════════════════════
# Unit tests for _condition_has_key helper
# ═══════════════════════════════════════════════════════════════════════════════


class TestConditionHasKey:
    """Direct unit tests for _condition_has_key()."""

    def test_exact_match(self):
        cond = {"StringEquals": {"iam:PassedToService": "bedrock.amazonaws.com"}}
        assert _condition_has_key(cond, "iam:PassedToService") is True

    def test_case_insensitive_match(self):
        """IAM condition keys are case-insensitive per AWS docs."""
        cond = {"StringEquals": {"iam:passedtoservice": "bedrock.amazonaws.com"}}
        assert _condition_has_key(cond, "iam:PassedToService") is True

    def test_mixed_case_key(self):
        cond = {"StringEquals": {"IAM:PASSEDTOSERVICE": "bedrock.amazonaws.com"}}
        assert _condition_has_key(cond, "iam:PassedToService") is True

    def test_no_false_positive_on_longer_key(self):
        """
        OLD BUG (str-based): "iam:PassedToServiceAccount" contains the
        substring "iam:PassedToService" → old code suppressed AIG004 finding
        even though the PassedToService condition was absent.

        New behaviour: exact match only — no false suppression.
        """
        cond = {"StringEquals": {"iam:PassedToServiceAccount": "123456789"}}
        # "iam:PassedToServiceAccount" must NOT match "iam:PassedToService"
        assert _condition_has_key(cond, "iam:PassedToService") is False

    def test_empty_condition(self):
        assert _condition_has_key({}, "iam:PassedToService") is False

    def test_none_condition(self):
        assert _condition_has_key(None, "iam:PassedToService") is False  # type: ignore[arg-type]

    def test_malformed_condition_value(self):
        """Condition operator has non-dict value — should not crash."""
        cond = {"StringEquals": "not-a-dict"}
        assert _condition_has_key(cond, "iam:PassedToService") is False

    def test_multiple_operators(self):
        cond = {
            "StringEquals": {"aws:RequestedRegion": "us-east-1"},
            "ArnLike": {"iam:PassedToService": "bedrock.amazonaws.com"},
        }
        assert _condition_has_key(cond, "iam:PassedToService") is True

    def test_aws_source_arn_found(self):
        cond = {"ArnLike": {"aws:SourceArn": "arn:aws:lambda:us-east-1:123:function:myFunc"}}
        assert _condition_has_key(cond, "aws:SourceArn") is True

    def test_aws_source_arn_case_variant(self):
        """aws:sourceArn (lowercase) must still match aws:SourceArn lookup."""
        cond = {"ArnLike": {"aws:sourceArn": "arn:aws:lambda:us-east-1:123:function:myFunc"}}
        assert _condition_has_key(cond, "aws:SourceArn") is True

    def test_condition_has_key_any_returns_true_on_first_match(self):
        cond = {"StringEquals": {"aws:PrincipalTag/team": "ml-ops"}}
        # Neither exact match but PrincipalTag prefix — not in scope for this helper
        # Test the helper finds aws:PrincipalTag/team when asked for it exactly
        assert _condition_has_key_any(cond, "aws:PrincipalTag/team", "aws:ResourceTag") is True

    def test_condition_has_key_any_returns_false_when_none_match(self):
        cond = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
        assert _condition_has_key_any(cond, "aws:PrincipalTag", "aws:ResourceTag") is False


# ═══════════════════════════════════════════════════════════════════════════════
# AIG004: PassRole + PassedToService — regression tests for str(condition) bug
# ═══════════════════════════════════════════════════════════════════════════════


class TestAIG004PassRoleConditionParsing:
    """AIG004 must fire when PassedToService is truly absent,
    and must NOT fire when it is present (even with unusual casing)."""

    def test_passrole_without_condition_fires(self):
        """Basic: PassRole with no condition → AIG004."""
        findings = scan_policy_document({
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
            }]
        })
        assert any(f.rule_id == "AIG004" for f in findings), (
            "AIG004 must fire for PassRole with no condition"
        )

    def test_passrole_with_correct_condition_no_finding(self):
        """PassRole with proper PassedToService → no AIG004."""
        findings = scan_policy_document({
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"iam:PassedToService": "bedrock.amazonaws.com"}
                },
            }]
        })
        assert not any(f.rule_id == "AIG004" for f in findings), (
            "AIG004 must NOT fire when iam:PassedToService is present"
        )

    def test_passrole_with_lowercase_condition_key_no_finding(self):
        """
        OLD FALSE-POSITIVE: condition key 'iam:passedtoservice' (lowercase)
        was not found by case-sensitive str() substring search → AIG004 fired
        even though the condition WAS correct.

        New behaviour: case-insensitive structural match → no AIG004.
        """
        findings = scan_policy_document({
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"iam:passedtoservice": "bedrock.amazonaws.com"}
                },
            }]
        })
        assert not any(f.rule_id == "AIG004" for f in findings), (
            "AIG004 must NOT fire when iam:passedtoservice (lowercase) is present — "
            "IAM condition keys are case-insensitive"
        )

    def test_passrole_with_passedtoserviceaccount_fires(self):
        """
        OLD FALSE-NEGATIVE: condition key 'iam:PassedToServiceAccount' contains
        the substring 'iam:PassedToService' → old str() check suppressed AIG004
        even though PassedToService was ABSENT.

        New behaviour: exact key match only → AIG004 fires correctly.
        """
        findings = scan_policy_document({
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"iam:PassedToServiceAccount": "123456789012"}
                },
            }]
        })
        assert any(f.rule_id == "AIG004" for f in findings), (
            "AIG004 MUST fire — 'iam:PassedToServiceAccount' is not the same as "
            "'iam:PassedToService'. Old str() check had a false-negative here."
        )


# ═══════════════════════════════════════════════════════════════════════════════
# AIG002: Wildcard action expansion — partial wildcards covering dangerous actions
# ═══════════════════════════════════════════════════════════════════════════════


class TestAIG002PartialWildcards:
    """AIG002 must now detect dangerous partial wildcards, not just '*' and 'svc:*'."""

    def test_iam_star_role_star_fires(self):
        """'iam:*Role*' expands to cover iam:PassRole, iam:CreateRole, etc."""
        findings = scan_policy_document({
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:*Role*",
                "Resource": "*",
            }]
        })
        assert any(f.rule_id == "AIG002" for f in findings), (
            "AIG002 must fire for 'iam:*Role*' — covers iam:PassRole (privilege escalation)"
        )

    def test_s3_get_star_fires(self):
        """'s3:Get*' expands to cover s3:GetObject (sensitive data)."""
        findings = scan_policy_document({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:Get*",
                "Resource": "*",
            }]
        })
        assert any(f.rule_id == "AIG002" for f in findings), (
            "AIG002 must fire for 's3:Get*' — covers s3:GetObject (sensitive data access)"
        )

    def test_bedrock_star_agent_star_fires(self):
        """'bedrock:*Agent*' expands to cover bedrock:CreateAgent, UpdateAgent."""
        findings = scan_policy_document({
            "Statement": [{
                "Effect": "Allow",
                "Action": "bedrock:*Agent*",
                "Resource": "*",
            }]
        })
        assert any(f.rule_id == "AIG002" for f in findings), (
            "AIG002 must fire for 'bedrock:*Agent*' — covers agent control-plane actions"
        )

    def test_ec2_describe_star_does_not_fire(self):
        """'ec2:Describe*' is read-only and does not cover any dangerous action."""
        findings = scan_policy_document({
            "Statement": [{
                "Effect": "Allow",
                "Action": "ec2:Describe*",
                "Resource": "*",
            }]
        })
        # ec2:Describe* is read-only, should not trigger AIG002
        aig002 = [f for f in findings if f.rule_id == "AIG002"]
        assert not aig002, (
            f"AIG002 must NOT fire for 'ec2:Describe*' — read-only actions. Got: {aig002}"
        )

    def test_explicit_star_still_fires(self):
        """Existing behaviour: bare '*' still fires AIG002."""
        findings = scan_policy_document({
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        })
        assert any(f.rule_id == "AIG002" for f in findings)

    def test_service_star_still_fires(self):
        """Existing behaviour: 'iam:*' still fires AIG002."""
        findings = scan_policy_document({
            "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]
        })
        assert any(f.rule_id == "AIG002" for f in findings)


# ═══════════════════════════════════════════════════════════════════════════════
# Trust policy: ExternalId / SourceArn structural checks
# ═══════════════════════════════════════════════════════════════════════════════


class TestTrustPolicyConditionParsing:
    """AIG-TP002/TP003 must use structural condition checking."""

    def _cross_account_trust(self, condition: dict) -> dict:
        return {
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole",
                "Condition": condition,
            }]
        }

    def test_tp002_fires_without_external_id(self):
        findings = scan_trust_policy(self._cross_account_trust({}))
        assert any(f.rule_id == "AIG-TP002" for f in findings)

    def test_tp002_no_finding_with_external_id(self):
        findings = scan_trust_policy(self._cross_account_trust({
            "StringEquals": {"sts:ExternalId": "shared-secret-abc123"}
        }))
        assert not any(f.rule_id == "AIG-TP002" for f in findings)

    def test_tp002_no_finding_with_lowercase_externalid_key(self):
        """Case-insensitive: 'sts:externalid' must match 'sts:ExternalId'."""
        findings = scan_trust_policy(self._cross_account_trust({
            "StringEquals": {"sts:externalid": "shared-secret"}
        }))
        assert not any(f.rule_id == "AIG-TP002" for f in findings), (
            "TP002 must NOT fire — 'sts:externalid' (lowercase) is the same "
            "condition key as 'sts:ExternalId' (IAM keys are case-insensitive)"
        )

    def test_tp003_no_finding_with_source_arn(self):
        findings = scan_trust_policy(self._cross_account_trust({
            "ArnLike": {"aws:SourceArn": "arn:aws:lambda:us-east-1:999:function:myFn"}
        }))
        assert not any(f.rule_id == "AIG-TP003" for f in findings)

    def test_tp003_no_finding_with_lowercase_source_arn(self):
        """'aws:sourceArn' (lowercase) must match 'aws:SourceArn' lookup."""
        findings = scan_trust_policy(self._cross_account_trust({
            "ArnLike": {"aws:sourceArn": "arn:aws:lambda:us-east-1:999:function:myFn"}
        }))
        assert not any(f.rule_id == "AIG-TP003" for f in findings), (
            "TP003 must NOT fire — 'aws:sourceArn' equals 'aws:SourceArn' case-insensitively"
        )
