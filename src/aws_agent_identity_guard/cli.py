from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import Finding, scan_policy_document


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan AWS IAM policy JSON for agent identity risks"
    )
    parser.add_argument("policy", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    findings = scan_policy_document(_load_json(args.policy))
    if args.format == "json":
        print(json.dumps({"findings": [f.to_dict() for f in findings]}, indent=2))
    else:
        _print_text(findings)
    return 1 if any(f.severity in {"high", "critical"} for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
