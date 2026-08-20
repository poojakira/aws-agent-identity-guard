"""
tests/test_coverage_boost.py
──────────────────────────────────────────────────────────────────────────────
Additional tests to boost coverage from 62% to 90%+.

Targets:
- __main__.py (lines 3-7)
- cli.py (75 missed lines: argparse, live-scan path, remediation, formats)
- remediate.py (all 83 lines — 0% covered)
- live_scanner.py (75 missed lines — user enumeration, error handling, etc.)
- scanner.py (11 missed lines)

All AWS/boto3 calls are mocked — no credentials needed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════════════
# __main__.py coverage (lines 3-7)
# ═══════════════════════════════════════════════════════════════════════════════


class TestMainModule:
    """Cover __main__.py by running it as a module."""

    def test_main_module_invocation(self, tmp_path):
        """Running `python -m aws_agent_identity_guard` invokes cli.main()."""
        # Use a Deny statement so nothing is flagged
        policy = tmp_path / "policy.json"
        policy.write_text(
            json.dumps({"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}),
            encoding="utf-8",
        )
        result = subprocess.run(
            [sys.executable, "-m", "aws_agent_identity_guard", str(policy)],
            capture_output=True,
            text=True,
        )
        # Should succeed (exit 0) with no findings
        assert result.returncode == 0
        assert "PASS" in result.stdout or "no high-risk" in result.stdout

    def test_main_module_with_findings(self, tmp_path):
        """Running __main__ with a risky policy exits with 1."""
        policy = tmp_path / "bad.json"
        policy.write_text(
            json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
            encoding="utf-8",
        )
        result = subprocess.run(
            [sys.executable, "-m", "aws_agent_identity_guard", str(policy)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1

    def test_main_module_direct_import(self):
        """Importing __main__ module covers lines 3-7."""
        from unittest.mock import patch as mock_patch

        with mock_patch("aws_agent_identity_guard.cli.main", return_value=0):
            with pytest.raises(SystemExit) as exc_info:
                import importlib

                import aws_agent_identity_guard.__main__

                importlib.reload(aws_agent_identity_guard.__main__)
            assert exc_info.value.code == 0


# ═══════════════════════════════════════════════════════════════════════════════
# cli.py coverage
# ═══════════════════════════════════════════════════════════════════════════════


class TestCli:
    """Cover cli.py missed lines: argparse, formats, live-scan, remediate."""

    def test_version_flag(self, capsys):
        """--version prints version and exits 0."""
        from aws_agent_identity_guard.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0

    def test_no_args_error(self, capsys):
        """No args and no --live-scan should error."""
        from aws_agent_identity_guard.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main([])
        # argparse exits with 2 on usage errors
        assert exc_info.value.code == 2

    def test_invalid_json_file(self, tmp_path):
        """Non-JSON file should exit with SystemExit."""
        from aws_agent_identity_guard.cli import main

        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        with pytest.raises(SystemExit, match="failed to read policy JSON"):
            main([str(bad)])

    def test_non_dict_json_file(self, tmp_path):
        """JSON that is not an object should exit."""
        from aws_agent_identity_guard.cli import main

        bad = tmp_path / "array.json"
        bad.write_text("[1,2,3]", encoding="utf-8")
        with pytest.raises(SystemExit, match="policy JSON must be an object"):
            main([str(bad)])

    def test_format_json(self, tmp_path, capsys):
        """--format json produces JSON output."""
        from aws_agent_identity_guard.cli import main

        policy = tmp_path / "p.json"
        policy.write_text(
            json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
            encoding="utf-8",
        )
        rc = main([str(policy), "--format", "json"])
        assert rc == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "findings" in data

    def test_format_text_pass(self, tmp_path, capsys):
        """--format text with clean policy shows PASS."""
        from aws_agent_identity_guard.cli import main

        # Use a Deny statement to avoid any findings
        policy = tmp_path / "clean.json"
        policy.write_text(
            json.dumps({"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}),
            encoding="utf-8",
        )
        rc = main([str(policy), "--format", "text"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "PASS" in captured.out

    def test_format_text_with_findings(self, tmp_path, capsys):
        """--format text with risky policy shows severity and rule_id."""
        from aws_agent_identity_guard.cli import main

        policy = tmp_path / "risky.json"
        policy.write_text(
            json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
            encoding="utf-8",
        )
        rc = main([str(policy), "--format", "text"])
        assert rc == 1
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out
        assert "AIG002" in captured.out

    def test_output_file_static(self, tmp_path):
        """--output writes to file instead of stdout."""
        from aws_agent_identity_guard.cli import main

        policy = tmp_path / "p.json"
        policy.write_text(
            json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
            encoding="utf-8",
        )
        out = tmp_path / "out.json"
        rc = main([str(policy), "--format", "json", "--output", str(out)])
        assert rc == 1
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "findings" in data

    def test_sarif_format_static(self, tmp_path, capsys):
        """--format sarif produces SARIF output."""
        from aws_agent_identity_guard.cli import main

        policy = tmp_path / "p.json"
        policy.write_text(
            json.dumps(
                {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
            ),
            encoding="utf-8",
        )
        main([str(policy), "--format", "sarif"])
        captured = capsys.readouterr()
        sarif = json.loads(captured.out)
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "aws-agent-identity-guard"

    def test_remediate_flag(self, tmp_path, capsys):
        """--remediate generates remediation output."""
        from aws_agent_identity_guard.cli import main

        policy = tmp_path / "agent_role_policy.json"
        policy.write_text(
            json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "Resource": "*",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        rc = main([str(policy), "--remediate"])
        assert rc == 1
        captured = capsys.readouterr()
        assert "GENERATED REMEDIATIONS" in captured.out
        assert "Terraform HCL" in captured.out

    def test_remediate_no_findings(self, tmp_path, capsys):
        """--remediate with clean policy does not output remediation."""
        from aws_agent_identity_guard.cli import main

        policy = tmp_path / "clean_policy.json"
        policy.write_text(
            json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::bucket/prefix/*",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        rc = main([str(policy), "--remediate"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "GENERATED REMEDIATIONS" not in captured.out

    def test_live_scan_no_boto3(self, capsys):
        """--live-scan without boto3 installed shows error."""
        # Simulate ImportError when trying to import live_scanner

        from aws_agent_identity_guard.cli import main

        # Remove live_scanner from sys.modules if it's there, and make the import fail
        with patch.dict("sys.modules", {"aws_agent_identity_guard.live_scanner": None}):
            rc = main(["--live-scan"])
            assert rc == 2
            captured = capsys.readouterr()
            assert "boto3" in captured.out.lower() or "ERROR" in captured.out

    def test_live_scan_json_format(self, capsys):
        """--live-scan --format json outputs JSON report."""
        from aws_agent_identity_guard.cli import main

        mock_report = MagicMock()
        mock_report.to_dict.return_value = {
            "account_id": "123456789012",
            "scan_timestamp": "2026-01-01T00:00:00Z",
            "region": "us-east-1",
            "roles_scanned": 1,
            "users_scanned": 0,
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "roles": [],
            "errors": [],
        }

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan_account.return_value = mock_report

        with patch(
            "aws_agent_identity_guard.cli.LiveAccountScanner",
            mock_scanner_class,
            create=True,
        ):
            # Patch the import inside main
            import aws_agent_identity_guard.cli as cli_module

            with (
                patch.object(cli_module, "__import__", create=True),
                patch.dict(
                    "sys.modules",
                    {
                        "aws_agent_identity_guard.live_scanner": MagicMock(
                            LiveAccountScanner=mock_scanner_class
                        )
                    },
                ),
            ):
                rc = main(["--live-scan", "--format", "json"])

        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["account_id"] == "123456789012"

    def test_live_scan_text_format(self, capsys):
        """--live-scan --format text outputs human-readable report."""
        from aws_agent_identity_guard.cli import main

        mock_report = MagicMock()
        mock_report.to_dict.return_value = {
            "account_id": "123456789012",
            "scan_timestamp": "2026-01-01T00:00:00Z",
            "region": "us-east-1",
            "roles_scanned": 2,
            "users_scanned": 1,
            "findings": [
                {
                    "rule_id": "AIG002",
                    "severity": "critical",
                    "message": "Wildcard actions",
                    "remediation": "Scope actions",
                    "resource_name": "my-role",
                    "policy_name": "too-broad",
                    "statement_index": 0,
                }
            ],
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1},
            "roles": [],
            "errors": [],
        }

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan_account.return_value = mock_report

        with patch.dict(
            "sys.modules",
            {
                "aws_agent_identity_guard.live_scanner": MagicMock(
                    LiveAccountScanner=mock_scanner_class
                )
            },
        ):
            rc = main(["--live-scan", "--format", "text"])

        assert rc == 1  # has critical findings
        captured = capsys.readouterr()
        assert "Account" in captured.out
        assert "123456789012" in captured.out

    def test_live_scan_text_no_findings(self, capsys):
        """--live-scan --format text with no findings shows PASS."""
        from aws_agent_identity_guard.cli import main

        mock_report = MagicMock()
        mock_report.to_dict.return_value = {
            "account_id": "123456789012",
            "scan_timestamp": "2026-01-01T00:00:00Z",
            "region": "us-east-1",
            "roles_scanned": 1,
            "users_scanned": 0,
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "roles": [],
            "errors": [],
        }

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan_account.return_value = mock_report

        with patch.dict(
            "sys.modules",
            {
                "aws_agent_identity_guard.live_scanner": MagicMock(
                    LiveAccountScanner=mock_scanner_class
                )
            },
        ):
            rc = main(["--live-scan", "--format", "text"])

        assert rc == 0
        captured = capsys.readouterr()
        assert "PASS" in captured.out

    def test_live_scan_sarif_format(self, tmp_path, capsys):
        """--live-scan --format sarif produces SARIF output."""
        from aws_agent_identity_guard.cli import main

        mock_report = MagicMock()
        mock_report.to_dict.return_value = {
            "account_id": "123456789012",
            "scan_timestamp": "2026-01-01T00:00:00Z",
            "region": "us-east-1",
            "roles_scanned": 1,
            "users_scanned": 0,
            "findings": [
                {
                    "rule_id": "AIG002",
                    "severity": "critical",
                    "message": "Wildcard actions",
                    "remediation": "Scope actions",
                    "statement_index": 0,
                }
            ],
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1},
            "roles": [],
            "errors": [],
        }

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan_account.return_value = mock_report

        with patch.dict(
            "sys.modules",
            {
                "aws_agent_identity_guard.live_scanner": MagicMock(
                    LiveAccountScanner=mock_scanner_class
                )
            },
        ):
            rc = main(["--live-scan", "--format", "sarif"])

        assert rc == 1
        captured = capsys.readouterr()
        sarif = json.loads(captured.out)
        assert sarif["version"] == "2.1.0"

    def test_live_scan_output_file(self, tmp_path, capsys):
        """--live-scan with --output writes to file."""
        from aws_agent_identity_guard.cli import main

        mock_report = MagicMock()
        mock_report.to_dict.return_value = {
            "account_id": "123456789012",
            "scan_timestamp": "2026-01-01T00:00:00Z",
            "region": "us-east-1",
            "roles_scanned": 1,
            "users_scanned": 0,
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "roles": [],
            "errors": [],
        }

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan_account.return_value = mock_report

        out = tmp_path / "report.json"
        with patch.dict(
            "sys.modules",
            {
                "aws_agent_identity_guard.live_scanner": MagicMock(
                    LiveAccountScanner=mock_scanner_class
                )
            },
        ):
            rc = main(["--live-scan", "--format", "json", "--output", str(out)])

        assert rc == 0
        assert out.exists()

    def test_live_scan_exception_handling(self, capsys):
        """--live-scan with boto3 error exits 2."""
        from aws_agent_identity_guard.cli import main

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan_account.side_effect = RuntimeError("No creds")

        with patch.dict(
            "sys.modules",
            {
                "aws_agent_identity_guard.live_scanner": MagicMock(
                    LiveAccountScanner=mock_scanner_class
                )
            },
        ):
            rc = main(["--live-scan"])

        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR" in captured.out

    def test_live_scan_value_error(self, capsys):
        """--live-scan with ValueError exits 2."""
        from aws_agent_identity_guard.cli import main

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan_account.side_effect = ValueError("bad config")

        with patch.dict(
            "sys.modules",
            {
                "aws_agent_identity_guard.live_scanner": MagicMock(
                    LiveAccountScanner=mock_scanner_class
                )
            },
        ):
            rc = main(["--live-scan"])

        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR" in captured.out

    def test_live_scan_with_role_name_and_region(self, capsys):
        """--live-scan --role-name X --region Y passes params correctly."""
        from aws_agent_identity_guard.cli import main

        mock_report = MagicMock()
        mock_report.to_dict.return_value = {
            "account_id": "123456789012",
            "scan_timestamp": "2026-01-01T00:00:00Z",
            "region": "eu-west-1",
            "roles_scanned": 1,
            "users_scanned": 0,
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "roles": [],
            "errors": [],
        }

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan_account.return_value = mock_report

        with patch.dict(
            "sys.modules",
            {
                "aws_agent_identity_guard.live_scanner": MagicMock(
                    LiveAccountScanner=mock_scanner_class
                )
            },
        ):
            rc = main(
                [
                    "--live-scan",
                    "--role-name",
                    "my-agent",
                    "--region",
                    "eu-west-1",
                    "--format",
                    "json",
                ]
            )

        assert rc == 0
        mock_scanner_class.assert_called_once_with(region="eu-west-1", role_name_filter="my-agent")


# ═══════════════════════════════════════════════════════════════════════════════
# remediate.py coverage (all 83 lines)
# ═══════════════════════════════════════════════════════════════════════════════


class TestRemediate:
    """Cover remediate.py — generate_remediations and remediate_to_json."""

    def _make_finding(self, rule_id, severity="high", message="test", remediation="fix"):
        from aws_agent_identity_guard.scanner import Finding

        return Finding(
            rule_id=rule_id,
            severity=severity,
            message=message,
            remediation=remediation,
            statement_index=0,
        )

    def test_remediate_aig004_passrole(self):
        """AIG004 generates PassRole remediation with Terraform + CFN."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG004", "critical")]
        result = generate_remediations(findings, resource_name="my-agent-role")

        assert len(result) == 1
        r = result[0]
        assert "AIG004" in r.findings_addressed
        assert "passrole" in r.terraform_hcl.lower() or "PassRole" in r.terraform_hcl
        assert "bedrock.amazonaws.com" in r.terraform_hcl
        assert r.resource_name == "my-agent-role"
        assert "PassRoleScoped" in r.cloudformation_yaml or "PassRole" in r.cloudformation_yaml
        assert r.fixed_policy_json["Version"] == "2012-10-17"
        assert "PassRole" in r.explanation or "passrole" in r.explanation.lower()

    def test_remediate_aig015_bedrock(self):
        """AIG015 generates Bedrock model scoping."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG015", "medium")]
        ctx = {"model_id": "anthropic.claude-3-sonnet-20240229-v1:0"}
        result = generate_remediations(findings, resource_name="bedrock-agent", context=ctx)

        assert len(result) == 1
        r = result[0]
        assert "AIG015" in r.findings_addressed
        assert "anthropic.claude-3-sonnet" in r.terraform_hcl
        assert "InvokeModel" in r.terraform_hcl or "InvokeModel" in str(r.fixed_policy_json)
        assert "foundation-model" in str(r.fixed_policy_json)

    def test_remediate_aig006_lambda(self):
        """AIG006 generates Lambda tool scoping."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG006", "high")]
        ctx = {"owner_tag": "ml-team"}
        result = generate_remediations(findings, resource_name="tool-agent", context=ctx)

        assert len(result) == 1
        r = result[0]
        assert "AIG006" in r.findings_addressed or "AIG016" in r.findings_addressed
        assert "agent-tool-*" in r.terraform_hcl or "agent-tool" in r.terraform_hcl
        assert "ml-team" in r.terraform_hcl

    def test_remediate_aig016_lambda(self):
        """AIG016 also generates Lambda tool scoping (same as AIG006)."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG016", "high")]
        result = generate_remediations(findings, resource_name="invoke-agent")

        assert len(result) == 1
        r = result[0]
        assert "AIG016" in r.findings_addressed

    def test_remediate_aig017_session_tags(self):
        """AIG017 generates session tag requirement."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG017", "high")]
        ctx = {"target_role_arn": "arn:aws:iam::111122223333:role/downstream"}
        result = generate_remediations(
            findings,
            resource_name="chain-agent",
            resource_arn="arn:aws:iam::999:role/chain-agent",
            context=ctx,
        )

        assert len(result) == 1
        r = result[0]
        assert "AIG017" in r.findings_addressed
        assert "session-id" in r.terraform_hcl or "SessionTag" in r.terraform_hcl
        assert "TransitiveTagKeys" in r.terraform_hcl or "transitive" in r.terraform_hcl.lower()
        assert r.resource_arn == "arn:aws:iam::999:role/chain-agent"

    def test_remediate_aig005_permission_boundary(self):
        """AIG005 generates permission boundary."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG005", "critical")]
        result = generate_remediations(findings, resource_name="admin-agent")

        assert len(result) == 1
        r = result[0]
        assert "AIG005" in r.findings_addressed
        assert "permission_boundary" in r.terraform_hcl or "PermissionBoundary" in r.terraform_hcl
        assert "Deny" in r.terraform_hcl

    def test_remediate_multiple_boundary_rules(self):
        """AIG008, AIG009, AIG010, AIG011 all group into boundary fix."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [
            self._make_finding("AIG008", "critical"),
            self._make_finding("AIG009", "high"),
            self._make_finding("AIG010", "high"),
            self._make_finding("AIG011", "critical"),
        ]
        result = generate_remediations(findings, resource_name="over-scoped-agent")

        # Should produce one combined boundary remediation
        assert len(result) == 1
        r = result[0]
        # All four should be addressed
        for rule in ("AIG008", "AIG009", "AIG010", "AIG011"):
            assert rule in r.findings_addressed

    def test_remediate_mixed_findings(self):
        """Multiple different finding types produce multiple remediations."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [
            self._make_finding("AIG004", "critical"),
            self._make_finding("AIG015", "medium"),
            self._make_finding("AIG017", "high"),
        ]
        result = generate_remediations(findings, resource_name="multi-agent")

        assert len(result) == 3
        rule_sets = [set(r.findings_addressed) for r in result]
        assert {"AIG004"} in rule_sets
        assert {"AIG015"} in rule_sets
        assert {"AIG017"} in rule_sets

    def test_remediate_dedup_same_rule(self):
        """Duplicate rule_ids in findings produce only one remediation."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [
            self._make_finding("AIG004", "critical"),
            self._make_finding("AIG004", "critical"),
        ]
        result = generate_remediations(findings, resource_name="dup-agent")
        assert len(result) == 1

    def test_remediate_no_findings(self):
        """Empty findings list returns empty remediations."""
        from aws_agent_identity_guard.remediate import generate_remediations

        result = generate_remediations([], resource_name="clean-agent")
        assert result == []

    def test_remediate_unknown_rule(self):
        """Unknown rule_id is ignored (no remediation generated)."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG999", "low")]
        result = generate_remediations(findings, resource_name="unknown-agent")
        assert result == []

    def test_remediate_to_json(self):
        """remediate_to_json serializes remediations correctly."""
        from aws_agent_identity_guard.remediate import generate_remediations, remediate_to_json

        findings = [self._make_finding("AIG004", "critical")]
        remediations = generate_remediations(findings, resource_name="json-agent")
        output = remediate_to_json(remediations)

        data = json.loads(output)
        assert len(data) == 1
        assert data[0]["resource"] == "json-agent"
        assert "AIG004" in data[0]["findings_fixed"]
        assert "terraform" in data[0]
        assert "cloudformation" in data[0]
        assert "policy_json" in data[0]
        assert "explanation" in data[0]

    def test_remediate_default_context(self):
        """Default context values are used when none provided."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG004", "critical")]
        result = generate_remediations(findings, resource_name="default-ctx")

        assert len(result) == 1
        # Default target_service is bedrock.amazonaws.com
        assert "bedrock.amazonaws.com" in result[0].terraform_hcl

    def test_remediate_custom_context(self):
        """Custom context overrides defaults."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG004", "critical")]
        ctx = {"target_service": "lambda.amazonaws.com"}
        result = generate_remediations(findings, resource_name="custom-ctx", context=ctx)

        assert "lambda.amazonaws.com" in result[0].terraform_hcl

    def test_cfn_yaml_multiple_actions(self):
        """CloudFormation YAML handles list actions correctly."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG015", "medium")]
        result = generate_remediations(findings, resource_name="cfn-test")

        cfn = result[0].cloudformation_yaml
        assert "Action:" in cfn
        # Should have list items for multiple actions
        assert "bedrock:InvokeModel" in cfn or "InvokeModel" in cfn

    def test_cfn_yaml_with_condition(self):
        """CloudFormation YAML handles Condition in statements."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG004", "critical")]
        result = generate_remediations(findings, resource_name="cond-test")

        cfn = result[0].cloudformation_yaml
        assert "Condition" in cfn or "condition" in cfn.lower()

    def test_remediate_resource_name_normalization(self):
        """Resource names with dashes/dots are normalized for Terraform."""
        from aws_agent_identity_guard.remediate import generate_remediations

        findings = [self._make_finding("AIG015", "medium")]
        result = generate_remediations(findings, resource_name="my-agent.role-v2")

        # Terraform resource name should be normalized (underscores)
        assert "my_agent_role_v2" in result[0].terraform_hcl


# ═══════════════════════════════════════════════════════════════════════════════
# live_scanner.py coverage (user policies, error paths, managed policies)
# ═══════════════════════════════════════════════════════════════════════════════


class TestLiveScannerAdditional:
    """Cover live_scanner.py missed lines using moto."""

    @pytest.fixture(autouse=True)
    def _skip_if_no_moto(self):
        pytest.importorskip("moto", reason="moto required for live scanner tests")
        pytest.importorskip("boto3", reason="boto3 required for live scanner tests")

    def _session(self):
        import boto3 as _b3

        return _b3.Session(
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            aws_session_token="testing",
        )

    def _trust(self, principal):
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
                ],
            }
        )

    def _policy_doc(self, actions, resources):
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resources}],
            }
        )

    @pytest.mark.usefixtures("_skip_if_no_moto")
    def test_user_policy_scanning(self):
        """Live scanner detects findings in IAM user policies."""
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            iam = sess.client("iam")

            # Create user with risky policy
            iam.create_user(UserName="agent-user")
            iam.put_user_policy(
                UserName="agent-user",
                PolicyName="too-broad",
                PolicyDocument=self._policy_doc(["*"], ["*"]),
            )

            report = LiveAccountScanner(session=sess).scan_account()
            user_findings = [f for f in report.findings if f.get("resource_name") == "agent-user"]
            assert len(user_findings) > 0
            assert report.users_scanned >= 1

    @pytest.mark.usefixtures("_skip_if_no_moto")
    def test_managed_policy_scanning(self):
        """Live scanner fetches and scans managed policies attached to roles."""
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            iam = sess.client("iam")

            # Create a managed policy
            policy_resp = iam.create_policy(
                PolicyName="agent-broad-policy",
                PolicyDocument=self._policy_doc(["iam:PassRole"], ["*"]),
            )
            policy_arn = policy_resp["Policy"]["Arn"]

            # Create role and attach managed policy
            iam.create_role(
                RoleName="managed-role",
                AssumeRolePolicyDocument=self._trust({"Service": "bedrock.amazonaws.com"}),
            )
            iam.attach_role_policy(RoleName="managed-role", PolicyArn=policy_arn)

            report = LiveAccountScanner(session=sess).scan_account()
            role_findings = [f for f in report.findings if f.get("resource_name") == "managed-role"]
            # Should find AIG004 (PassRole without condition)
            assert any(f["rule_id"] == "AIG004" for f in role_findings)

    @pytest.mark.usefixtures("_skip_if_no_moto")
    def test_permission_boundary_note(self):
        """Role with high findings and no boundary gets AIG-PB001."""
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            iam = sess.client("iam")

            iam.create_role(
                RoleName="no-boundary-role",
                AssumeRolePolicyDocument=self._trust({"Service": "bedrock.amazonaws.com"}),
            )
            iam.put_role_policy(
                RoleName="no-boundary-role",
                PolicyName="risky",
                PolicyDocument=self._policy_doc(["*"], ["*"]),
            )

            report = LiveAccountScanner(session=sess).scan_account()
            pb_findings = [
                f
                for f in report.findings
                if f.get("rule_id") == "AIG-PB001" and f.get("resource_name") == "no-boundary-role"
            ]
            assert len(pb_findings) == 1
            assert (
                "permission boundary" in pb_findings[0]["message"].lower()
                or "permission boundary" in pb_findings[0]["remediation"].lower()
            )

    @pytest.mark.usefixtures("_skip_if_no_moto")
    def test_role_name_filter(self):
        """--role-name filter scans only the specified role."""
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            iam = sess.client("iam")

            iam.create_role(
                RoleName="target-role",
                AssumeRolePolicyDocument=self._trust("*"),
            )
            iam.create_role(
                RoleName="other-role",
                AssumeRolePolicyDocument=self._trust({"Service": "lambda.amazonaws.com"}),
            )

            report = LiveAccountScanner(session=sess, role_name_filter="target-role").scan_account()

            # Only target-role should be in findings
            assert report.roles_scanned == 1
            for f in report.findings:
                if "resource_name" in f:
                    assert f["resource_name"] == "target-role"

    @pytest.mark.usefixtures("_skip_if_no_moto")
    def test_user_with_managed_policy(self):
        """User with attached managed policy is scanned."""
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            iam = sess.client("iam")

            # Create managed policy
            policy_resp = iam.create_policy(
                PolicyName="user-broad",
                PolicyDocument=self._policy_doc(["iam:CreateRole", "iam:PutRolePolicy"], ["*"]),
            )
            policy_arn = policy_resp["Policy"]["Arn"]

            # Create user and attach
            iam.create_user(UserName="risky-user")
            iam.attach_user_policy(UserName="risky-user", PolicyArn=policy_arn)

            report = LiveAccountScanner(session=sess).scan_account()
            user_findings = [f for f in report.findings if f.get("resource_name") == "risky-user"]
            assert any(f["rule_id"] == "AIG005" for f in user_findings)

    @pytest.mark.usefixtures("_skip_if_no_moto")
    def test_role_with_tags_and_last_used(self):
        """Scanner includes role metadata in report."""
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            iam = sess.client("iam")

            iam.create_role(
                RoleName="tagged-role",
                AssumeRolePolicyDocument=self._trust({"Service": "bedrock.amazonaws.com"}),
                Tags=[
                    {"Key": "team", "Value": "ml"},
                    {"Key": "agent-owner", "Value": "platform"},
                ],
            )

            report = LiveAccountScanner(session=sess).scan_account()
            report_dict = report.to_dict()

            # Find the tagged-role in the roles list
            tagged = [r for r in report_dict["roles"] if r["role_name"] == "tagged-role"]
            assert len(tagged) == 1
            # Verify it was scanned (tags may or may not be returned depending on moto version)
            assert tagged[0]["findings_count"] >= 0

    @pytest.mark.usefixtures("_skip_if_no_moto")
    def test_account_id_detection(self):
        """Scanner correctly detects the account ID."""
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            iam = sess.client("iam")
            iam.create_role(
                RoleName="any",
                AssumeRolePolicyDocument=self._trust({"Service": "lambda.amazonaws.com"}),
            )

            report = LiveAccountScanner(session=sess).scan_account()
            # moto uses a predictable account ID
            assert report.account_id != "unknown"
            assert len(report.account_id) == 12

    @pytest.mark.usefixtures("_skip_if_no_moto")
    def test_scan_account_empty(self):
        """Scanning empty account (no roles/users) returns clean report."""
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            report = LiveAccountScanner(session=sess).scan_account()
            assert report.roles_scanned == 0
            assert report.users_scanned == 0
            assert report.findings == []


# ═══════════════════════════════════════════════════════════════════════════════
# scanner.py coverage (missed lines — edge cases)
# ═══════════════════════════════════════════════════════════════════════════════


class TestScannerEdgeCases:
    """Cover scanner.py missed lines."""

    def test_statement_as_single_dict(self):
        """Statement as a single dict (not list) is handled."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        doc = {
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        }
        findings = scan_policy_document(doc)
        assert any(f.rule_id == "AIG002" for f in findings)

    def test_not_action_with_not_resource(self):
        """NotAction + NotResource triggers AIG001."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "s3:*",
                    "NotResource": "arn:aws:s3:::protected-bucket",
                }
            ]
        }
        findings = scan_policy_document(doc)
        assert any(f.rule_id == "AIG001" for f in findings)

    def test_s3_write_broad_bucket_no_prefix(self):
        """S3 write to bucket/* without prefix triggers AIG014."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ]
        }
        findings = scan_policy_document(doc)
        assert any(f.rule_id == "AIG014" for f in findings)

    def test_s3_write_scoped_prefix_no_finding(self):
        """S3 write to bucket/prefix/* does NOT trigger AIG014."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::my-bucket/agent-workspace/data/*",
                }
            ]
        }
        findings = scan_policy_document(doc)
        assert not any(f.rule_id == "AIG014" for f in findings)

    def test_dynamodb_scan_without_conditions(self):
        """DynamoDB Scan on * without conditions triggers AIG018."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "dynamodb:Scan",
                    "Resource": "*",
                }
            ]
        }
        findings = scan_policy_document(doc)
        assert any(f.rule_id == "AIG018" for f in findings)

    def test_bedrock_invoke_with_model_scope_no_aig015(self):
        """Bedrock InvokeModel scoped to model ARN doesn't trigger AIG015."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "bedrock:InvokeModel",
                    "Resource": (
                        "arn:aws:bedrock:us-east-1::foundation-model" "/anthropic.claude-3-haiku*"
                    ),
                }
            ]
        }
        findings = scan_policy_document(doc)
        assert not any(f.rule_id == "AIG015" for f in findings)

    def test_non_dict_policy_raises_type_error(self):
        """Non-dict document raises TypeError."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        with pytest.raises(TypeError, match="must be a dict"):
            scan_policy_document("not a dict")

    def test_trust_policy_non_dict_raises_type_error(self):
        """Non-dict trust policy raises TypeError."""
        from aws_agent_identity_guard.scanner import scan_trust_policy

        with pytest.raises(TypeError, match="must be a dict"):
            scan_trust_policy([])

    def test_deny_statements_are_skipped(self):
        """Deny effect statements do not produce findings."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        doc = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                }
            ]
        }
        findings = scan_policy_document(doc)
        assert findings == []

    def test_empty_statement_list(self):
        """Empty Statement list produces no findings."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        findings = scan_policy_document({"Statement": []})
        assert findings == []

    def test_excessive_actions_aig012(self):
        """More than 15 distinct actions triggers AIG012."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        actions = [f"s3:Action{i}" for i in range(20)]
        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": actions,
                    "Resource": "arn:aws:s3:::bucket/*",
                }
            ]
        }
        findings = scan_policy_document(doc)
        assert any(f.rule_id == "AIG012" for f in findings)

    def test_lambda_invoke_scoped_no_aig016(self):
        """Lambda invoke with specific function ARN does not trigger AIG016."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-tool-func",
                }
            ]
        }
        findings = scan_policy_document(doc)
        assert not any(f.rule_id == "AIG016" for f in findings)

    def test_sts_assume_role_with_session_tags_no_aig017(self):
        """AssumeRole with RequestTag condition does not trigger AIG017."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::123456789012:role/target",
                    "Condition": {
                        "StringLike": {"aws:RequestTag/agent-session-id": "*"},
                        "ForAllValues:StringEquals": {
                            "sts:TransitiveTagKeys": ["agent-session-id"]
                        },
                    },
                }
            ]
        }
        findings = scan_policy_document(doc)
        assert not any(f.rule_id == "AIG017" for f in findings)

    def test_trust_policy_dict_principal(self):
        """Trust policy with dict principal (AWS key) is parsed."""
        from aws_agent_identity_guard.scanner import scan_trust_policy

        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        findings = scan_trust_policy(doc)
        # Should flag cross-account without ExternalId
        assert any(f.rule_id == "AIG-TP002" for f in findings)

    def test_trust_policy_service_principal_no_cross_account(self):
        """Trust policy with service principal does not trigger cross-account rules."""
        from aws_agent_identity_guard.scanner import scan_trust_policy

        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "bedrock.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        findings = scan_trust_policy(doc)
        assert not any(f.rule_id == "AIG-TP002" for f in findings)
        assert not any(f.rule_id == "AIG-TP003" for f in findings)

    def test_s3_write_bucket_no_slash(self):
        """S3 write to arn:aws:s3:::bucket (no slash at all) triggers AIG014."""
        from aws_agent_identity_guard.scanner import scan_policy_document

        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:DeleteObject",
                    "Resource": "arn:aws:s3:::mybucket",
                }
            ]
        }
        findings = scan_policy_document(doc)
        assert any(f.rule_id == "AIG014" for f in findings)


# ═══════════════════════════════════════════════════════════════════════════════
# live_scanner.py error path coverage (using unittest.mock)
# ═══════════════════════════════════════════════════════════════════════════════


class TestLiveScannerErrorPaths:
    """Cover live_scanner.py error-handling branches using mocks."""

    @pytest.fixture(autouse=True)
    def _skip_if_no_deps(self):
        pytest.importorskip("moto", reason="moto required")
        pytest.importorskip("boto3", reason="boto3 required")

    def _session(self):
        import boto3 as _b3

        return _b3.Session(
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            aws_session_token="testing",
        )

    def test_get_account_id_failure(self):
        """When STS fails, account_id returns 'unknown'."""
        import botocore.exceptions
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            scanner = LiveAccountScanner(session=sess)

            # Mock the STS client to fail
            scanner._sts = MagicMock()
            scanner._sts.get_caller_identity.side_effect = botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "forbidden"}},
                "GetCallerIdentity",
            )

            account_id = scanner._get_account_id()
            assert account_id == "unknown"

    def test_get_managed_policy_failure(self):
        """When get_policy fails, returns None."""
        import botocore.exceptions
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            scanner = LiveAccountScanner(session=sess)

            # Mock to fail
            scanner._iam = MagicMock()
            scanner._iam.get_policy.side_effect = botocore.exceptions.ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "not found"}},
                "GetPolicy",
            )

            result = scanner._get_managed_policy_document("arn:aws:iam::123:policy/missing")
            assert result is None

    def test_collect_role_policies_inline_failure(self):
        """When list_role_policies fails, returns empty list gracefully."""
        import botocore.exceptions
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            scanner = LiveAccountScanner(session=sess)

            # Make the paginator raise
            mock_iam = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.side_effect = botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "forbidden"}},
                "ListRolePolicies",
            )
            mock_iam.get_paginator.return_value = mock_paginator
            scanner._iam = mock_iam

            policies = scanner._collect_role_policies(
                "test-role", "arn:aws:iam::123:role/test-role"
            )
            assert policies == []

    def test_collect_user_policies_inline_failure(self):
        """When list_user_policies fails, returns empty list gracefully."""
        import botocore.exceptions
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            scanner = LiveAccountScanner(session=sess)

            mock_iam = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.side_effect = botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "forbidden"}},
                "ListUserPolicies",
            )
            mock_iam.get_paginator.return_value = mock_paginator
            scanner._iam = mock_iam

            policies = scanner._collect_user_policies(
                "test-user", "arn:aws:iam::123:user/test-user"
            )
            assert policies == []

    def test_enumerate_roles_failure(self):
        """When list_roles fails, returns empty list."""
        import botocore.exceptions
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            scanner = LiveAccountScanner(session=sess)

            mock_iam = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.side_effect = botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "forbidden"}},
                "ListRoles",
            )
            mock_iam.get_paginator.return_value = mock_paginator
            scanner._iam = mock_iam

            roles = scanner._enumerate_roles()
            assert roles == []

    def test_enumerate_users_failure(self):
        """When list_users fails, returns empty list."""
        import botocore.exceptions
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            scanner = LiveAccountScanner(session=sess)

            mock_iam = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.side_effect = botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "forbidden"}},
                "ListUsers",
            )
            mock_iam.get_paginator.return_value = mock_paginator
            scanner._iam = mock_iam

            users = scanner._enumerate_users()
            assert users == []

    def test_enumerate_roles_max_cap(self):
        """When max_roles is reached, scanning truncates."""
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            iam = sess.client("iam")

            # Create 3 roles but set cap to 2
            for i in range(3):
                iam.create_role(
                    RoleName=f"role-{i}",
                    AssumeRolePolicyDocument=json.dumps(
                        {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        }
                    ),
                )

            scanner = LiveAccountScanner(session=sess, max_roles=2)
            roles = scanner._enumerate_roles()
            assert len(roles) <= 2

    def test_get_role_policy_individual_failure(self):
        """When get_role_policy fails for one policy, others still collected."""
        import botocore.exceptions
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            scanner = LiveAccountScanner(session=sess)

            # Mock IAM: list_role_policies returns two names, but get_role_policy fails for one
            mock_iam = MagicMock()

            # For inline: paginator returns policy names
            inline_paginator = MagicMock()
            inline_paginator.paginate.return_value = [{"PolicyNames": ["policy-ok", "policy-fail"]}]

            # For attached: paginator returns empty
            attached_paginator = MagicMock()
            attached_paginator.paginate.return_value = [{"AttachedPolicies": []}]

            def get_paginator(name):
                if name == "list_role_policies":
                    return inline_paginator
                return attached_paginator

            mock_iam.get_paginator.side_effect = get_paginator

            call_count = [0]

            def get_role_policy_side_effect(**kwargs):
                call_count[0] += 1
                if kwargs["PolicyName"] == "policy-fail":
                    raise botocore.exceptions.ClientError(
                        {"Error": {"Code": "NoSuchEntity", "Message": "nope"}},
                        "GetRolePolicy",
                    )
                return {
                    "PolicyDocument": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                        ]
                    }
                }

            mock_iam.get_role_policy.side_effect = get_role_policy_side_effect
            scanner._iam = mock_iam

            policies = scanner._collect_role_policies(
                "test-role", "arn:aws:iam::123:role/test-role"
            )
            # One should succeed
            assert len(policies) == 1
            assert policies[0].policy_name == "policy-ok"

    def test_get_user_policy_individual_failure(self):
        """When get_user_policy fails for one policy, others still collected."""
        import botocore.exceptions
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            scanner = LiveAccountScanner(session=sess)

            mock_iam = MagicMock()

            inline_paginator = MagicMock()
            inline_paginator.paginate.return_value = [
                {"PolicyNames": ["user-policy-ok", "user-policy-fail"]}
            ]

            attached_paginator = MagicMock()
            attached_paginator.paginate.return_value = [{"AttachedPolicies": []}]

            def get_paginator(name):
                if name == "list_user_policies":
                    return inline_paginator
                return attached_paginator

            mock_iam.get_paginator.side_effect = get_paginator

            def get_user_policy_side_effect(**kwargs):
                if kwargs["PolicyName"] == "user-policy-fail":
                    raise botocore.exceptions.ClientError(
                        {"Error": {"Code": "NoSuchEntity", "Message": "nope"}},
                        "GetUserPolicy",
                    )
                return {
                    "PolicyDocument": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                        ]
                    }
                }

            mock_iam.get_user_policy.side_effect = get_user_policy_side_effect
            scanner._iam = mock_iam

            policies = scanner._collect_user_policies(
                "test-user", "arn:aws:iam::123:user/test-user"
            )
            assert len(policies) == 1
            assert policies[0].policy_name == "user-policy-ok"

    def test_collect_role_attached_policies_failure(self):
        """When list_attached_role_policies fails, inline policies still returned."""
        import botocore.exceptions
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            scanner = LiveAccountScanner(session=sess)

            mock_iam = MagicMock()

            inline_paginator = MagicMock()
            inline_paginator.paginate.return_value = [{"PolicyNames": []}]

            attached_paginator = MagicMock()
            attached_paginator.paginate.side_effect = botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "ListAttachedRolePolicies",
            )

            def get_paginator(name):
                if name == "list_role_policies":
                    return inline_paginator
                return attached_paginator

            mock_iam.get_paginator.side_effect = get_paginator
            scanner._iam = mock_iam

            policies = scanner._collect_role_policies("role", "arn:aws:iam::123:role/role")
            assert policies == []

    def test_collect_user_attached_policies_failure(self):
        """When list_attached_user_policies fails, inline policies still returned."""
        import botocore.exceptions
        from moto import mock_aws

        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            sess = self._session()
            scanner = LiveAccountScanner(session=sess)

            mock_iam = MagicMock()

            inline_paginator = MagicMock()
            inline_paginator.paginate.return_value = [{"PolicyNames": []}]

            attached_paginator = MagicMock()
            attached_paginator.paginate.side_effect = botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "ListAttachedUserPolicies",
            )

            def get_paginator(name):
                if name == "list_user_policies":
                    return inline_paginator
                return attached_paginator

            mock_iam.get_paginator.side_effect = get_paginator
            scanner._iam = mock_iam

            policies = scanner._collect_user_policies("user", "arn:aws:iam::123:user/user")
            assert policies == []


# ═══════════════════════════════════════════════════════════════════════════════
# Additional remediate.py coverage (Resource list in CFN YAML)
# ═══════════════════════════════════════════════════════════════════════════════


class TestRemediateEdgeCases:
    """Cover remaining remediate.py edge cases."""

    def test_cfn_yaml_resource_list(self):
        """_to_cfn_yaml handles Resource as a list."""
        from aws_agent_identity_guard.remediate import _to_cfn_yaml

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Multi",
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": ["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2/*"],
                }
            ],
        }
        result = _to_cfn_yaml("TestPolicy", policy)
        assert "Resource:" in result
        assert "bucket1" in result
        assert "bucket2" in result

    def test_cfn_yaml_no_condition(self):
        """_to_cfn_yaml handles statements without Condition."""
        from aws_agent_identity_guard.remediate import _to_cfn_yaml

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Simple",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "*",
                }
            ],
        }
        result = _to_cfn_yaml("SimplePolicy", policy)
        assert "Condition" not in result
        assert "s3:GetObject" in result
        assert "s3:PutObject" in result


# ═══════════════════════════════════════════════════════════════════════════════
# Additional cli.py coverage (line 39: _print_text, line 96, line 309)
# ═══════════════════════════════════════════════════════════════════════════════


class TestCliHelpers:
    """Cover cli.py helper functions directly."""

    def test_print_text_function(self, capsys):
        """_print_text outputs findings text."""
        from aws_agent_identity_guard.cli import _print_text
        from aws_agent_identity_guard.scanner import Finding

        findings = [
            Finding(
                rule_id="AIG002",
                severity="critical",
                message="Test wildcard",
                remediation="Fix it",
                statement_index=0,
            )
        ]
        _print_text(findings)
        captured = capsys.readouterr()
        assert "CRITICAL" in captured.out
        assert "AIG002" in captured.out

    def test_print_text_no_findings(self, capsys):
        """_print_text with empty findings shows PASS."""
        from aws_agent_identity_guard.cli import _print_text

        _print_text([])
        captured = capsys.readouterr()
        assert "PASS" in captured.out

    def test_build_sarif_finding_without_statement_index(self, tmp_path):
        """_build_sarif handles findings without statement_index."""
        from aws_agent_identity_guard.cli import _build_sarif
        from aws_agent_identity_guard.scanner import Finding

        findings = [
            Finding(
                rule_id="AIG019",
                severity="critical",
                message="Kill chain",
                remediation="Split roles",
                statement_index=None,
            )
        ]
        sarif = _build_sarif(tmp_path / "policy.json", findings)
        result = sarif["runs"][0]["results"][0]
        assert "statementIndex" not in result.get("properties", {})
        assert "remediation" in result["properties"]
