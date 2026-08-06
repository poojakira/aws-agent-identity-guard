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
                        "version": "0.1.0",
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan AWS IAM policy JSON for agent identity risks"
    )
    parser.add_argument("policy", type=Path)
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    args = parser.parse_args(argv)

    findings = scan_policy_document(_load_json(args.policy))
    if args.format == "json":
        print(json.dumps({"findings": [f.to_dict() for f in findings]}, indent=2))
    elif args.format == "sarif":
        print(json.dumps(_build_sarif(args.policy, findings), indent=2))
    else:
        _print_text(findings)
    return 1 if any(f.severity in {"high", "critical"} for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
