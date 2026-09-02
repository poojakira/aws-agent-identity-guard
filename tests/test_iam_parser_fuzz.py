"""
Hypothesis-based property tests for the IAM JSON parser.

These tests fuzz the parser with randomly generated malformed, edge-case, and
unicode-heavy inputs to verify:
1. The parser never raises an unhandled exception (it degrades gracefully)
2. The parser never returns incorrect results for known-good inputs
3. The parser handles all IAM JSON edge cases without crashing

Why this matters: IAM policies in the wild have non-standard shapes. Teams
copy-paste from Stack Overflow, Terraform generates unusual structures, and
attackers may craft policies to trigger parser edge cases.
"""
from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aws_agent_identity_guard.scanner import (
    _as_list,
    _condition_has_key,
    _statements,
    scan_policy_document,
    scan_trust_policy,
)

# ---------------------------------------------------------------------------
# Strategy helpers
# ---------------------------------------------------------------------------

# Any scalar or container value hypothesis might throw at a policy field.
_any_value = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.text(),
    st.binary(),
    st.lists(st.text()),
    st.dictionaries(st.text(), st.text()),
)


# ---------------------------------------------------------------------------
# 1. scan_policy_document — never crashes on arbitrary input
# ---------------------------------------------------------------------------


@given(_any_value)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_scan_policy_never_crashes(value: object) -> None:
    """scan_policy_document must either return a list[Finding] (for dict input)
    or raise *only* TypeError (for non-dict input).  Any other exception is a
    parser bug that violates the graceful-degradation contract.

    CWE-20: Improper Input Validation — untrusted policy JSON may have any shape.
    """
    try:
        result = scan_policy_document(value)  # type: ignore[arg-type]
        # If we get here, input was accepted — result must be a list.
        assert isinstance(result, list), (
            f"scan_policy_document returned {type(result).__name__} instead of list"
        )
    except TypeError:
        # Expected: the function documents that non-dict input raises TypeError.
        pass


# ---------------------------------------------------------------------------
# 2. scan_trust_policy — never crashes on arbitrary input
# ---------------------------------------------------------------------------


@given(_any_value)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_scan_trust_never_crashes(value: object) -> None:
    """scan_trust_policy must either return a list[Finding] or raise only TypeError.

    Same contract as scan_policy_document — trust policies come from
    AssumeRolePolicyDocument which may also have unusual shapes.
    """
    try:
        result = scan_trust_policy(value)  # type: ignore[arg-type]
        assert isinstance(result, list), (
            f"scan_trust_policy returned {type(result).__name__} instead of list"
        )
    except TypeError:
        pass


# ---------------------------------------------------------------------------
# 3. _as_list — always returns list[str]
# ---------------------------------------------------------------------------


@given(_any_value)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_as_list_always_returns_list(value: object) -> None:
    """_as_list(v) must always return a list where every element is a str.

    This is a load-bearing invariant: all downstream action/resource loops
    assume they are iterating over strings.
    """
    result = _as_list(value)
    assert isinstance(result, list), (
        f"_as_list returned {type(result).__name__}, expected list"
    )
    for item in result:
        assert isinstance(item, str), (
            f"_as_list produced non-str element {item!r} (type {type(item).__name__})"
        )


# ---------------------------------------------------------------------------
# 4. _condition_has_key — case-insensitive matching
# ---------------------------------------------------------------------------


@given(
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/-_",
        min_size=1,
    ),
    st.text(min_size=1),
)
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_condition_has_key_case_insensitive(k: str, v: str) -> None:
    """_condition_has_key must return the same result regardless of the
    target_key casing — IAM condition key names are case-insensitive.

    This guards against regressions where a case-normalisation step is
    accidentally dropped from one code path.

    The key strategy is constrained to the ASCII alphabet that real IAM
    condition keys use (service prefixes such as ``aws:``/``iam:``, plus
    ``/``-delimited tag suffixes). AWS condition-key case-insensitivity is
    defined over ASCII; feeding arbitrary Unicode would test an impossible
    property, since ``str.upper()``/``str.lower()`` are not invertible for
    characters like the German ``ß`` or the Turkish dotless ``ı``.
    """
    condition = {"StringEquals": {k: "val"}}
    result_upper = _condition_has_key(condition, k.upper())
    result_lower = _condition_has_key(condition, k.lower())
    assert result_upper == result_lower, (
        f"Case-insensitive mismatch for key {k!r}: "
        f"upper={result_upper}, lower={result_lower}"
    )
    # Also: a key that IS in the condition must always return True regardless
    # of how we capitalise the lookup.
    assert result_lower is True, (
        f"_condition_has_key returned False for key {k!r} that is present in condition"
    )


# ---------------------------------------------------------------------------
# 5. _statements — never crashes on arbitrary Statement list members
# ---------------------------------------------------------------------------


@given(st.dictionaries(st.text(), st.text()))
@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
def test_statements_with_unicode_keys(d: dict[str, str]) -> None:
    """_statements must handle Statement entries with arbitrary unicode keys and
    string values without crashing.

    Terraform and CDK sometimes emit policy documents with unusual key names
    or non-ASCII characters.  The parser must not choke on any of them.
    """
    document = {"Statement": [d]}
    result = _statements(document)
    # _statements must return a list; every item must be a dict.
    assert isinstance(result, list)
    for item in result:
        assert isinstance(item, dict), (
            f"_statements returned a non-dict item: {item!r}"
        )


# ---------------------------------------------------------------------------
# 6. Wildcard Action as string (not list) still fires AIG002
# ---------------------------------------------------------------------------


def test_wildcard_action_string_not_list() -> None:
    """When Action is the single string '*' (not ['*']), AIG002 must still fire.

    Some policy documents encode a lone wildcard as a JSON string rather than
    a single-element array.  _as_list() normalises this, and the scanner must
    handle both representations identically.
    """
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",       # string, not list
                "Resource": "*",
            }
        ]
    }
    findings = scan_policy_document(policy)
    rule_ids = [f.rule_id for f in findings]
    assert "AIG002" in rule_ids, (
        f"Expected AIG002 for wildcard string Action, got rule IDs: {rule_ids}"
    )


# ---------------------------------------------------------------------------
# 7. NotAction as list still fires AIG001
# ---------------------------------------------------------------------------


def test_nested_notaction_fires_aig001() -> None:
    """NotAction as a list of specific actions must still trigger AIG001.

    NotAction/NotResource grant everything EXCEPT what is listed — this is
    almost always over-broad for agent policies.  The rule must fire whether
    NotAction is a string or a list.
    """
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": ["iam:CreateRole", "s3:DeleteBucket"],
                "Resource": "*",
            }
        ]
    }
    findings = scan_policy_document(policy)
    rule_ids = [f.rule_id for f in findings]
    assert "AIG001" in rule_ids, (
        f"Expected AIG001 for NotAction list, got rule IDs: {rule_ids}"
    )


# ---------------------------------------------------------------------------
# 8. Deny statements produce zero findings
# ---------------------------------------------------------------------------


def test_deny_statement_not_scanned() -> None:
    """A statement with Effect=Deny must produce no findings.

    The scanner only lints Allow statements — Deny statements are a narrowing
    control and should never generate noise.  This also prevents false positives
    when a service-control-policy-style Deny is present in a mixed document.
    """
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "NotAction": "iam:CreateRole",
            }
        ]
    }
    findings = scan_policy_document(policy)
    assert findings == [], (
        f"Expected no findings for Deny statement, got: {findings}"
    )
