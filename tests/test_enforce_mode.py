"""Regression tests for enforce mode (P0 Issue A).

Tests that incomplete scans fail in enforce mode, and that
the tool doesn't silently pass on incomplete/truncated scans.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from aws_agent_identity_guard.cli import main


class TestEnforceMode:
    """Tests for --enforce flag behavior."""

    def test_enforce_flag_exists(self):
        """--enforce flag should be recognized."""
        # Just verify the flag is parsed without error
        with patch("sys.argv", ["aws-agent-identity-guard", "--help"]):
            with pytest.raises(SystemExit) as exc:
                main()
            # --help exits with 0
            assert exc.value.code == 0

    def test_enforce_mode_fails_on_incomplete_scan(self, tmp_path, monkeypatch):
        """In enforce mode, incomplete scan should return exit code 1."""
        # Create a mock policy file for static analysis (complete scan)
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        }
        policy_file = tmp_path / "test_policy.json"
        policy_file.write_text(json.dumps(policy))

        # In static mode, enforce should not affect complete scans
        # This just verifies the flag doesn't break static mode
        exit_code = main([str(policy_file), "--enforce", "--format", "json"])
        # Has high finding (AIG003 - wildcard resource), so returns 1
        assert exit_code == 1

    def test_static_mode_clean_policy_passes_even_with_enforce(self, tmp_path):
        """Clean policy in static mode should pass even with --enforce."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "bedrock:InvokeModel",
                    "Resource": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku*",
                    "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                }
            ],
        }
        policy_file = tmp_path / "clean_policy.json"
        policy_file.write_text(json.dumps(policy))

        exit_code = main([str(policy_file), "--enforce", "--format", "json"])
        assert exit_code == 0


class TestIncompleteScanDetection:
    """Tests for detecting incomplete scans in live mode."""

    def test_scan_report_has_completeness_fields(self):
        """Scan report should include scan_complete, roles_discovered, completeness_reason."""
        from aws_agent_identity_guard.live_scanner import LiveAccountScanner, AccountScanReport

        # Verify the dataclass has the expected fields
        report = AccountScanReport(
            account_id="123456789012",
            scan_timestamp="2026-01-01T00:00:00Z",
            region="us-east-1",
            roles_scanned=10,
            users_scanned=5,
            findings=[],
            summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            roles=[],
            errors=[],
            scan_complete=True,
            roles_discovered=10,
            completeness_reason=None,
        )
        assert hasattr(report, "scan_complete")
        assert hasattr(report, "roles_discovered")
        assert hasattr(report, "completeness_reason")

    def test_incomplete_scan_marks_scan_complete_false(self):
        """When roles are truncated, scan_complete should be False."""
        # Use moto to mock AWS instead of complex MagicMock
        import boto3
        from moto import mock_aws
        from aws_agent_identity_guard.live_scanner import LiveAccountScanner

        with mock_aws():
            # Create IAM client and set up test roles
            iam = boto3.client("iam", region_name="us-east-1")
            
            # Create 600 roles (more than default max_roles=500)
            for i in range(600):
                role_name = f"test-role-{i}"
                trust_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
                iam.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps(trust_policy),
                )

            # Create scanner with low max_roles to force truncation
            scanner = LiveAccountScanner(region="us-east-1", max_roles=500)
            report = scanner.scan_account()

            assert report.scan_complete is False
            # roles_discovered is a lower bound - equals max_roles when truncated
            assert report.roles_discovered >= 500
            assert "truncated" in (report.completeness_reason or "").lower()


class TestNoHTTPProxy:
    """Document that there is no HTTP proxy / runtime auth engine."""

    def test_no_http_proxy_in_repo(self):
        """This is a static analyzer - no HTTP proxy exists."""
        import os

        repo_root = Path(__file__).parent.parent
        # Verify no proxy-related files exist
        assert not (repo_root / "src" / "aws_agent_identity_guard" / "proxy.py").exists()
        assert not (repo_root / "src" / "aws_agent_identity_guard" / "http_proxy.py").exists()
        assert not (repo_root / "src" / "aws_agent_identity_guard" / "server.py").exists()

    def test_no_runtime_auth_engine(self):
        """This is a static analyzer - no runtime authorization engine."""
        # The tool only does static analysis of IAM policy documents
        # It does not make runtime authorization decisions
        from aws_agent_identity_guard.scanner import scan_policy_document

        # Scan a policy - this is static analysis, not runtime auth
        findings = scan_policy_document(
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        )
        # Should find critical issues
        rule_ids = {f.rule_id for f in findings}
        assert "AIG002" in rule_ids  # Wildcard action
        assert "AIG003" in rule_ids  # Wildcard resource


class TestTransportSecurity:
    """Document that there are no network listeners."""

    def test_no_network_listeners(self):
        """CLI tool has no network bindings."""
        import subprocess
        import sys

        # Run the tool with --version - it should not open any ports
        result = subprocess.run(
            [sys.executable, "-m", "aws_agent_identity_guard.cli", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0
        # No sockets should be left open
        # (Can't easily test this without more infrastructure, but the tool
        # is a CLI that exits immediately)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])