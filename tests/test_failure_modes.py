"""
tests/test_failure_modes.py
─────────────────────────────────────────────────────────────────────────────
Tests for failure modes: invalid input, missing files, malformed policies,
large documents, and encoding errors.

These verify the tool's behavior at the boundaries — ensuring it reports
errors clearly via exit code 2 (SystemExit) and handles edge cases gracefully
without crashing or producing misleading output.
"""

from __future__ import annotations

import json

import pytest

from aws_agent_identity_guard import scan_policy_document
from aws_agent_identity_guard.cli import main

# ═══════════════════════════════════════════════════════════════════════════════
# INVALID JSON INPUT
# ═══════════════════════════════════════════════════════════════════════════════


class TestInvalidJsonInput:
    """CLI should exit 2 when the file contains invalid JSON."""

    def test_truncated_json(self, tmp_path):
        """Truncated JSON (missing closing brace) → SystemExit."""
        bad_file = tmp_path / "truncated.json"
        bad_file.write_text('{"Statement": [{"Effect": "Allow"', encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            main([str(bad_file)])
        # SystemExit with a string message (from _load_json)
        assert "failed to read policy JSON" in str(exc_info.value)

    def test_completely_invalid_json(self, tmp_path):
        """Random text that is not JSON at all → SystemExit."""
        bad_file = tmp_path / "garbage.json"
        bad_file.write_text("this is not json at all!!!", encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            main([str(bad_file)])
        assert "failed to read policy JSON" in str(exc_info.value)

    def test_json_array_not_object(self, tmp_path):
        """JSON array instead of object → SystemExit."""
        bad_file = tmp_path / "array.json"
        bad_file.write_text('[{"Statement": []}]', encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            main([str(bad_file)])
        assert "policy JSON must be an object" in str(exc_info.value)

    def test_json_scalar(self, tmp_path):
        """JSON scalar (string) instead of object → SystemExit."""
        bad_file = tmp_path / "scalar.json"
        bad_file.write_text('"just a string"', encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            main([str(bad_file)])
        assert "policy JSON must be an object" in str(exc_info.value)

    def test_empty_file(self, tmp_path):
        """Empty file (zero bytes) → SystemExit."""
        bad_file = tmp_path / "empty.json"
        bad_file.write_text("", encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            main([str(bad_file)])
        assert "failed to read policy JSON" in str(exc_info.value)


# ═══════════════════════════════════════════════════════════════════════════════
# MISSING FILE
# ═══════════════════════════════════════════════════════════════════════════════


class TestMissingFile:
    """CLI should exit 2 when the policy file does not exist."""

    def test_nonexistent_file(self, tmp_path):
        """Path to a file that does not exist → SystemExit."""
        missing = tmp_path / "does_not_exist.json"

        with pytest.raises(SystemExit) as exc_info:
            main([str(missing)])
        assert "failed to read policy JSON" in str(exc_info.value)

    def test_directory_instead_of_file(self, tmp_path):
        """Passing a directory path instead of a file → SystemExit."""
        with pytest.raises(SystemExit) as exc_info:
            main([str(tmp_path)])
        assert "failed to read policy JSON" in str(exc_info.value)


# ═══════════════════════════════════════════════════════════════════════════════
# EMPTY POLICY DOCUMENT
# ═══════════════════════════════════════════════════════════════════════════════


class TestEmptyPolicyDocument:
    """Empty or minimal policy documents should be handled gracefully."""

    def test_empty_object(self):
        """Empty dict {} should not crash — returns empty findings."""
        findings = scan_policy_document({})
        assert isinstance(findings, list)

    def test_empty_statement_list(self):
        """Policy with Statement: [] should return no findings."""
        findings = scan_policy_document({"Statement": []})
        assert findings == []

    def test_empty_object_via_cli(self, tmp_path):
        """CLI with empty JSON object should exit 0 (no findings)."""
        policy_file = tmp_path / "empty_policy.json"
        policy_file.write_text("{}", encoding="utf-8")

        exit_code = main([str(policy_file)])
        assert exit_code == 0

    def test_empty_statement_via_cli(self, tmp_path):
        """CLI with empty Statement list should exit 0 (no findings)."""
        policy_file = tmp_path / "empty_stmts.json"
        policy_file.write_text('{"Statement": []}', encoding="utf-8")

        exit_code = main([str(policy_file)])
        assert exit_code == 0


# ═══════════════════════════════════════════════════════════════════════════════
# MALFORMED POLICY (missing or wrong-typed fields)
# ═══════════════════════════════════════════════════════════════════════════════


class TestMalformedPolicy:
    """Policies with missing or incorrectly-typed fields should not crash."""

    def test_missing_statement_field(self):
        """Policy object without Statement key should not crash."""
        findings = scan_policy_document({"Version": "2012-10-17"})
        assert isinstance(findings, list)

    def test_statement_is_string_not_list(self):
        """Statement as a string instead of list should not crash."""
        findings = scan_policy_document({"Statement": "not a list"})
        assert isinstance(findings, list)

    def test_statement_entry_is_string(self):
        """Statement containing a string entry instead of dict should not crash."""
        findings = scan_policy_document({"Statement": ["not a dict"]})
        assert isinstance(findings, list)

    def test_statement_missing_effect(self):
        """Statement without Effect field should not crash."""
        findings = scan_policy_document(
            {"Statement": [{"Action": "s3:GetObject", "Resource": "*"}]}
        )
        assert isinstance(findings, list)

    def test_statement_missing_action_and_notaction(self):
        """Statement without Action or NotAction should not crash."""
        findings = scan_policy_document({"Statement": [{"Effect": "Allow", "Resource": "*"}]})
        assert isinstance(findings, list)

    def test_statement_missing_resource(self):
        """Statement without Resource should not crash."""
        findings = scan_policy_document(
            {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject"}]}
        )
        assert isinstance(findings, list)

    def test_action_is_integer(self):
        """Action as an integer instead of string/list should not crash."""
        findings = scan_policy_document(
            {"Statement": [{"Effect": "Allow", "Action": 12345, "Resource": "*"}]}
        )
        assert isinstance(findings, list)

    def test_null_values_in_statement(self):
        """Null values in statement fields should not crash."""
        findings = scan_policy_document(
            {"Statement": [{"Effect": None, "Action": None, "Resource": None}]}
        )
        assert isinstance(findings, list)


# ═══════════════════════════════════════════════════════════════════════════════
# VERY LARGE POLICY DOCUMENT
# ═══════════════════════════════════════════════════════════════════════════════


class TestLargePolicyDocument:
    """Large policy documents should be handled without crashing or hanging."""

    def test_many_statements(self):
        """Policy with 500 statements should complete without error."""
        statements = [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::bucket-{i}/*",
            }
            for i in range(500)
        ]
        findings = scan_policy_document({"Statement": statements})
        assert isinstance(findings, list)

    def test_many_actions_per_statement(self):
        """Statement with 200 actions should complete without error."""
        actions = [f"s3:Action{i}" for i in range(200)]
        findings = scan_policy_document(
            {"Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
        )
        assert isinstance(findings, list)
        # Should trigger AIG012 (excessive action breadth > 15)
        assert any(f.rule_id == "AIG012" for f in findings)

    def test_large_policy_via_cli(self, tmp_path):
        """CLI with a large policy file should complete and exit normally."""
        statements = [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::bucket-{i}/*",
            }
            for i in range(100)
        ]
        policy = {"Version": "2012-10-17", "Statement": statements}
        policy_file = tmp_path / "large_policy.json"
        policy_file.write_text(json.dumps(policy), encoding="utf-8")

        exit_code = main([str(policy_file)])
        assert exit_code in (0, 1)


# ═══════════════════════════════════════════════════════════════════════════════
# NON-UTF8 CONTENT
# ═══════════════════════════════════════════════════════════════════════════════


class TestNonUtf8Content:
    """Files with non-UTF8 encoding should cause SystemExit (cannot decode)."""

    def test_latin1_encoded_file(self, tmp_path):
        """File encoded in Latin-1 with non-ASCII bytes → SystemExit."""
        bad_file = tmp_path / "latin1.json"
        # Write bytes that are valid Latin-1 but invalid UTF-8
        content = b'{"Statement": [{"Effect": "Allow", "Action": "s3:Get\xff\xfe"}]}'
        bad_file.write_bytes(content)

        with pytest.raises(SystemExit) as exc_info:
            main([str(bad_file)])
        assert "failed to read policy JSON" in str(exc_info.value)

    def test_null_bytes_in_file(self, tmp_path):
        """File containing null bytes → SystemExit (invalid JSON)."""
        bad_file = tmp_path / "nullbytes.json"
        content = b'{"Statement": [\x00\x00]}'
        bad_file.write_bytes(content)

        with pytest.raises(SystemExit) as exc_info:
            main([str(bad_file)])
        assert "failed to read policy JSON" in str(exc_info.value)

    def test_binary_file(self, tmp_path):
        """Completely binary file → SystemExit."""
        bad_file = tmp_path / "binary.json"
        bad_file.write_bytes(bytes(range(256)))

        with pytest.raises(SystemExit) as exc_info:
            main([str(bad_file)])
        assert "failed to read policy JSON" in str(exc_info.value)
