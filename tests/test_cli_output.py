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
