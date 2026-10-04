"""AWS IAM Access Analyzer differential-validation helpers.

The helpers compare the local deterministic rule engine with AWS
Access Analyzer ValidatePolicy on the same exact policy bytes. This is
interoperability evidence only; neither side computes complete effective
permissions for a deployed principal.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

from .scanner import scan_policy_document


def _aws_validate(client: Any, policy: dict[str, Any]) -> list[dict[str, Any]]:
    response = client.validate_policy(
        policyDocument=json.dumps(policy, separators=(",", ":")),
        policyType="IDENTITY_POLICY",
    )
    findings = response.get("findings", [])
    return findings if isinstance(findings, list) else []


def compare_policy(client: Any, path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    policy = json.loads(raw.decode("utf-8"))
    local = scan_policy_document(policy)
    aws_findings = _aws_validate(client, policy)
    return {
        "policy": path.name,
        "policy_sha256": hashlib.sha256(raw).hexdigest(),
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
        "aws_issue_codes": sorted(
            {
                str(item.get("issueCode", "UNKNOWN"))
                for item in aws_findings
                if isinstance(item, dict)
            }
        ),
        "scope": (
            "Differential policy-validation evidence only; neither side computes "
            "the complete effective permissions of a deployed principal."
        ),
    }
