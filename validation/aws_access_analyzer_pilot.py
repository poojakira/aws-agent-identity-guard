"""Differential validation pilot against AWS IAM Access Analyzer.

This script is intentionally separate from normal CI. It requires an operator-supplied
AWS identity with permission to call access-analyzer:ValidatePolicy. It never mutates
AWS resources and never prints credentials.

The result is interoperability evidence, not proof of effective permissions or
production safety.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from aws_agent_identity_guard.scanner import scan_policy_document


def _aws_validate(client: Any, policy: dict[str, Any]) -> list[dict[str, Any]]:
    response = client.validate_policy(
        policyDocument=json.dumps(policy, separators=(",", ":")),
        policyType="IDENTITY_POLICY",
    )
    findings = response.get("findings", [])
    return findings if isinstance(findings, list) else []


def compare_policy(client: Any, path: Path) -> dict[str, Any]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    local = scan_policy_document(policy)
    aws_findings = _aws_validate(client, policy)
    return {
        "policy": path.name,
        "local_finding_count": len(local),
        "local_rule_ids": sorted({finding.rule_id for finding in local}),
        "aws_finding_count": len(aws_findings),
        "aws_finding_types": sorted(
            {
                str(item.get("findingType", "UNKNOWN"))
                for item in aws_findings
                if isinstance(item, dict)
            }
        ),
        "scope": (
            "Differential policy-validation evidence only; neither side computes "
            "the complete effective permissions of a deployed principal."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("policies", nargs="+", type=Path)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, default=Path("validation/access-analyzer-report.json"))
    args = parser.parse_args()

    import boto3

    client = boto3.client("accessanalyzer", region_name=args.region)
    results = [compare_policy(client, path) for path in args.policies]
    payload = {
        "validator": "aws-iam-access-analyzer-validate-policy",
        "region": args.region,
        "results": results,
        "claim_boundary": (
            "This run compares static findings on the same documents. It is not "
            "customer validation, deployment evidence, or an effective-permissions proof."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output} for {len(results)} policies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
