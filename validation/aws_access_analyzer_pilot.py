"""Operator-facing AWS IAM Access Analyzer differential-validation pilot.

Requires an operator-supplied AWS identity with
access-analyzer:ValidatePolicy. The command performs no AWS mutations and does
not print credentials.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aws_agent_identity_guard.access_analyzer_validation import compare_policy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("policies", nargs="+", type=Path)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("validation/access-analyzer-report.json"),
    )
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
