"""Regression tests for CLI --output handling in static-analysis mode.

Guards against a regression where `--format sarif --output FILE` (the exact
invocation documented in the README's CI integration) silently printed to
stdout instead of writing the requested file, which broke the
`github/codeql-action/upload-sarif` step in the documented workflow.
"""

from __future__ import annotations

import json

from aws_agent_identity_guard.cli import main

# A policy that must produce at least one high/critical finding.
_BAD_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "bedrock:*",
            "Resource": "*",
        }
    ],
}


def _write_policy(tmp_path):
    p = tmp_path / "agent_policy.json"
    p.write_text(json.dumps(_BAD_POLICY), encoding="utf-8")
    return p


def test_sarif_output_writes_file(tmp_path):
    policy = _write_policy(tmp_path)
    out = tmp_path / "results.sarif"

    exit_code = main([str(policy), "--format", "sarif", "--output", str(out)])

    # High/critical findings present -> exit 1 (CI merge gate).
    assert exit_code == 1
    # The documented CI step depends on this file existing.
    assert out.exists(), "--output did not write the SARIF file in static mode"

    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc.get("version") == "2.1.0"
    assert "$schema" in doc
    assert doc["runs"][0]["results"], "expected at least one SARIF result"


def test_json_output_writes_file(tmp_path):
    policy = _write_policy(tmp_path)
    out = tmp_path / "results.json"

    exit_code = main([str(policy), "--format", "json", "--output", str(out)])

    assert exit_code == 1
    assert out.exists(), "--output did not write the JSON file in static mode"

    doc = json.loads(out.read_text(encoding="utf-8"))
    assert "findings" in doc
    assert doc["findings"], "expected at least one finding"


def test_output_creates_parent_directory(tmp_path):
    policy = _write_policy(tmp_path)
    out = tmp_path / "nested" / "dir" / "results.sarif"

    exit_code = main([str(policy), "--format", "sarif", "--output", str(out)])

    assert exit_code == 1
    assert out.exists(), "--output did not create missing parent directories"


# --- SARIF 2.1.0 conformance ------------------------------------------------
# We validate the emitted SARIF against the required structural invariants of
# the SARIF 2.1.0 specification (OASIS). This is a self-contained validator so
# the tool keeps ZERO runtime dependencies and the test suite does not need a
# network fetch of the published schema. The invariants checked below are the
# MUST-level requirements from the spec that GitHub Code Scanning enforces on
# upload: sarifLog.version, runs[].tool.driver.name, result.ruleId/ruleIndex
# coherence, result.level enum, and message.text presence.

_SARIF_VALID_LEVELS = {"none", "note", "warning", "error"}


def _assert_sarif_2_1_0_conformant(doc: dict) -> None:
    # sarifLog object (§3.13)
    assert doc.get("version") == "2.1.0", "sarifLog.version MUST be '2.1.0'"
    assert isinstance(doc.get("$schema", ""), str) and doc["$schema"].endswith(
        "sarif-schema-2.1.0.json"
    ), "sarifLog.$schema MUST reference the 2.1.0 schema"
    runs = doc.get("runs")
    assert isinstance(runs, list) and runs, "sarifLog.runs MUST be a non-empty array"

    for run in runs:
        # run.tool.driver (§3.14.6, §3.18)
        driver = run["tool"]["driver"]
        assert (
            isinstance(driver.get("name"), str) and driver["name"]
        ), "toolComponent.name is REQUIRED"
        rules = driver.get("rules", [])
        assert isinstance(rules, list)
        rule_ids = [r["id"] for r in rules]
        # reportingDescriptor.id MUST be unique within driver.rules (§3.49.3)
        assert len(rule_ids) == len(set(rule_ids)), "driver.rules[].id MUST be unique"
        for r in rules:
            assert isinstance(r.get("id"), str) and r["id"], "reportingDescriptor.id REQUIRED"

        # run.results (§3.14.23)
        results = run.get("results", [])
        assert isinstance(results, list)
        for res in results:
            # result.message.text is REQUIRED for our results (§3.27.11, §3.11)
            assert res["message"]["text"], "result.message.text REQUIRED"
            # result.level MUST be a valid enum value (§3.27.10)
            assert (
                res.get("level") in _SARIF_VALID_LEVELS
            ), f"result.level {res.get('level')!r} not in SARIF enum"
            # ruleId / ruleIndex coherence (§3.27.5, §3.27.6)
            assert isinstance(res.get("ruleId"), str) and res["ruleId"]
            idx = res.get("ruleIndex")
            if idx is not None:
                assert 0 <= idx < len(rules), "result.ruleIndex out of range"
                assert (
                    rules[idx]["id"] == res["ruleId"]
                ), "result.ruleIndex MUST point to the rule with matching id"
            # each result MUST reference a declared rule
            assert res["ruleId"] in rule_ids, "result.ruleId MUST be declared in driver.rules"
            # physicalLocation.artifactLocation.uri present (§3.28, §3.4)
            loc = res["locations"][0]["physicalLocation"]["artifactLocation"]
            assert isinstance(loc.get("uri"), str) and loc["uri"], "artifactLocation.uri REQUIRED"


def test_sarif_output_is_2_1_0_conformant(tmp_path):
    """The emitted SARIF must satisfy the MUST-level SARIF 2.1.0 invariants
    that GitHub Code Scanning enforces on upload."""
    policy = _write_policy(tmp_path)
    out = tmp_path / "results.sarif"

    exit_code = main([str(policy), "--format", "sarif", "--output", str(out)])
    assert exit_code == 1

    doc = json.loads(out.read_text(encoding="utf-8"))
    _assert_sarif_2_1_0_conformant(doc)


def test_sarif_clean_policy_still_conformant(tmp_path):
    """A policy with no findings must still emit a schema-conformant SARIF log
    (empty results array is valid) so CI upload never fails on a clean scan."""
    clean = tmp_path / "clean.json"
    clean.write_text(
        json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": (
                            "arn:aws:bedrock:us-east-1::" "foundation-model/anthropic.claude-v2"
                        ),
                        "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "clean.sarif"
    exit_code = main([str(clean), "--format", "sarif", "--output", str(out)])
    assert exit_code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    _assert_sarif_2_1_0_conformant(doc)
    assert doc["runs"][0]["results"] == []
