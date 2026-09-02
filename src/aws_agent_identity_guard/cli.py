from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import Finding, scan_policy_document


def _pkg_version() -> str:
    """Return the package version (single source of truth in __init__)."""
    from . import __version__

    return __version__


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SystemExit(f"failed to read policy JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit("policy JSON must be an object")
    return data


def _print_text(findings: list[Finding]) -> None:
    if not findings:
        print("PASS: no high-risk agent IAM findings")
        return
    for finding in findings:
        loc = f" statement={finding.statement_index}" if finding.statement_index is not None else ""
        print(f"{finding.severity.upper()} {finding.rule_id}{loc}: {finding.message}")
        print(f"  remediation: {finding.remediation}")


# SARIF severity mapping: SARIF uses "error" / "warning" / "note"
_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Stable URI for the tool rules — points at the repo
_TOOL_URI = "https://github.com/poojakira/aws-agent-identity-guard"


def _build_sarif(policy_path: Path, findings: list[Finding]) -> dict:
    """Return a SARIF 2.1.0-compliant result object."""
    # Collect unique rules (deduped by rule_id)
    seen_rules: dict[str, dict] = {}
    for f in findings:
        if f.rule_id not in seen_rules:
            seen_rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("-", ""),
                "shortDescription": {"text": f.message},
                "helpUri": _TOOL_URI,
                "properties": {"severity": f.severity},
            }

    rules = list(seen_rules.values())
    rule_index: dict[str, int] = {r["id"]: i for i, r in enumerate(rules)}

    results = []
    for f in findings:
        result: dict = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": policy_path.as_posix(),
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                }
            ],
        }
        if f.statement_index is not None:
            result["properties"] = {
                "statementIndex": f.statement_index,
                "remediation": f.remediation,
            }
        else:
            result["properties"] = {"remediation": f.remediation}
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aws-agent-identity-guard",
                        "version": _pkg_version(),
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "artifacts": [
                    {
                        "location": {
                            "uri": policy_path.as_posix(),
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                ],
            }
        ],
    }


def _print_live_text(report: dict) -> None:
    """Print a live-scan report in human-readable format."""
    print(f"Account : {report['account_id']}")
    print(f"Region  : {report['region']}")
    print(f"Scanned : {report['roles_scanned']} roles, {report['users_scanned']} users")
    print(f"Summary : {report['summary']}")
    print()
    if not report["findings"]:
        print("PASS: no findings")
        return
    for f in report["findings"]:
        resource = f.get("resource_name") or f.get("resource_arn", "?")
        policy = f" [{f['policy_name']}]" if f.get("policy_name") else ""
        print(f"{f['severity'].upper()} {f['rule_id']} {resource}{policy}: {f['message']}")
        print(f"  remediation: {f['remediation']}")


def main(argv: list[str] | None = None) -> int:
    from . import __version__

    parser = argparse.ArgumentParser(
        description="Scan AWS IAM policy JSON for agent identity risks"
    )

    # --version prints "aws-agent-identity-guard <version>" and exits 0,
    # matching the RUNBOOK's documented verification step.
    parser.add_argument(
        "--version",
        action="version",
        version=f"aws-agent-identity-guard {__version__}",
    )

    # Static analysis (existing behaviour)
    parser.add_argument(
        "policy",
        type=Path,
        nargs="?",
        help="Path to a local IAM policy JSON file (static analysis mode).",
    )

    # Live scan mode
    parser.add_argument(
        "--live-scan",
        action="store_true",
        help=(
            "Scan the live AWS account using Boto3. "
            "Requires AWS credentials and iam:List*/Get* permissions. "
            "Install boto3 with: pip install 'aws-agent-identity-guard[live]'"
        ),
    )
    parser.add_argument(
        "--role-name",
        default=None,
        help="Scan only this specific IAM role name (used with --live-scan).",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region for live scanning (default: session default or us-east-1).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write output to this file instead of stdout.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
    )
    parser.add_argument(
        "--remediate",
        action="store_true",
        help=(
            "Generate IaC remediation code (Terraform HCL + CloudFormation YAML) "
            "for each finding. Outputs ready-to-apply infrastructure fixes."
        ),
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help=(
            "Enforce mode: fail on incomplete scans (truncated, errors) in addition to "
            "high/critical findings. Use in CI/CD gates to prevent partial scans from passing."
        ),
    )
    args = parser.parse_args(argv)

    # ── Live scan mode ────────────────────────────────────────────────────────
    if args.live_scan:
        try:
            from .live_scanner import LiveAccountScanner  # noqa: PLC0415
        except ImportError:
            print(
                "ERROR: boto3 is not installed. "
                "Run: pip install 'aws-agent-identity-guard[live]'",
                flush=True,
            )
            return 2

        try:
            scanner = LiveAccountScanner(
                region=args.region,
                role_name_filter=args.role_name,
            )
            report = scanner.scan_account()
        except (ImportError, ValueError) as exc:
            print(f"ERROR: configuration problem: {exc}")
            return 2
        except Exception as exc:  # noqa: BLE001
            # Boto3 ClientError, NoCredentialsError, etc.
            # Surface the real error — do not swallow it
            print(f"ERROR during live scan: {type(exc).__name__}: {exc}")
            return 2

        report_dict = report.to_dict()
        has_high = (
            report_dict["summary"].get("critical", 0) + report_dict["summary"].get("high", 0) > 0
        )

        # Enforce mode: fail on incomplete scans
        scan_complete = report_dict.get("scan_complete", True)
        has_errors = len(report_dict.get("errors", [])) > 0
        enforce_fail = args.enforce and (not scan_complete or has_errors)

        if args.format == "json":
            output_text = json.dumps(report_dict, indent=2, default=str)
        elif args.format == "sarif":
            # Convert live findings to SARIF format
            from .scanner import Finding  # noqa: PLC0415

            sarif_findings = [
                Finding(
                    rule_id=f["rule_id"],
                    severity=f["severity"],
                    message=f["message"],
                    remediation=f["remediation"],
                    statement_index=f.get("statement_index"),
                )
                for f in report_dict["findings"]
            ]
            sarif_path = args.output or Path(f"scan-{report_dict['account_id']}.sarif")
            output_text = json.dumps(_build_sarif(sarif_path, sarif_findings), indent=2)
        else:
            _print_live_text(report_dict)
            if enforce_fail:
                if not scan_complete:
                    reason = report_dict.get("completeness_reason", "unknown reason")
                    print(f"ENFORCE FAIL: Incomplete scan - {reason}")
                if has_errors:
                    print(f"ENFORCE FAIL: Scan errors - {report_dict['errors']}")
            return 1 if (has_high or enforce_fail) else 0

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output_text, encoding="utf-8")
            print(f"Written to {args.output}")
        else:
            print(output_text)

        return 1 if (has_high or enforce_fail) else 0

    # ── Static analysis mode ──────────────────────────────────────────────────
    if args.policy is None:
        parser.error("Either provide a policy JSON file or use --live-scan")

    findings = scan_policy_document(_load_json(args.policy))
    if args.format == "json":
        output_text = json.dumps({"findings": [f.to_dict() for f in findings]}, indent=2)
    elif args.format == "sarif":
        output_text = json.dumps(_build_sarif(args.policy, findings), indent=2)
    else:
        output_text = None

    if output_text is not None:
        # Honor --output for machine-readable formats so the documented CI
        # integration (write results.sarif, then upload-sarif) actually works.
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output_text, encoding="utf-8")
            print(f"Written to {args.output}")
        else:
            print(output_text)
    else:
        _print_text(findings)

    # ── Remediation output ────────────────────────────────────────────────────
    if getattr(args, "remediate", False) and findings:
        from .remediate import generate_remediations  # noqa: PLC0415

        role_name = args.policy.stem.replace("_policy", "").replace("_", "-")
        remediations = generate_remediations(findings, resource_name=role_name)
        if remediations:
            print("\n" + "=" * 70)
            print("GENERATED REMEDIATIONS (AI-Powered Infrastructure Automation)")
            print("=" * 70)
            for r in remediations:
                print(f"\n--- Fix for {', '.join(r.findings_addressed)} ---")
                print(f"Explanation: {r.explanation}")
                print("\nTerraform HCL:")
                print(r.terraform_hcl)
                print()

    return 1 if any(f.severity in {"high", "critical"} for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
