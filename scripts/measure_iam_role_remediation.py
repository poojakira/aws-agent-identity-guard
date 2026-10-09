"""Compare full read-only IAM account snapshots, requiring authorization sign-off."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def measure(before_path: Path, after_path: Path, validation_path: Path) -> dict:
    before = json.loads(before_path.read_text(encoding="utf-8"))
    after = json.loads(after_path.read_text(encoding="utf-8"))
    validations = json.loads(validation_path.read_text(encoding="utf-8"))
    for name, report in (("before", before), ("after", after)):
        if report.get("scan_complete") is not True or report.get("errors"):
            raise ValueError(f"{name}: incomplete AWS role scan")
        if report.get("roles_discovered") != report.get("roles_scanned"):
            raise ValueError(f"{name}: missing or truncated roles")
        if not report.get("account_id") or report["account_id"] == "unknown":
            raise ValueError(f"{name}: missing AWS account identity")
    if before["account_id"] != after["account_id"]:
        raise ValueError("Cannot compare different AWS accounts")

    def roles(report):
        entries = report.get("roles", [])
        names = [r.get("role_arn") for r in entries]
        if any(not x for x in names) or len(set(names)) != len(names):
            raise ValueError("Missing or duplicate role ARN")
        return {r["role_arn"]: r for r in entries}

    left, right = roles(before), roles(after)
    if set(left) != set(right):
        raise ValueError("Role inventories differ; reconcile before reporting a percentage")
    if not isinstance(validations, dict):
        raise ValueError("Validation file must map role ARNs to evidence")

    def flagged(row):
        return int(row.get("critical", 0)) + int(row.get("high", 0)) > 0

    originally_flagged = {arn for arn, data in left.items() if flagged(data)}
    if not originally_flagged:
        raise ValueError("No initially flagged roles; percentage is undefined")
    confirmed = set()
    missing_validation = set()
    for arn in originally_flagged:
        if flagged(right[arn]):
            continue
        v = validations.get(arn, {})
        if (
            v.get("authorization_verified") is True
            and v.get("required_actions_verified") is True
            and v.get("change_approved") is True
            and v.get("evidence_ref")
            and v.get("environment") == "live_aws"
        ):
            confirmed.add(arn)
        else:
            missing_validation.add(arn)
    return {
        "account_id": before["account_id"],
        "before_timestamp": before.get("scan_timestamp"),
        "after_timestamp": after.get("scan_timestamp"),
        "roles_scanned": len(left),
        "initial_high_or_critical_flagged_roles": len(originally_flagged),
        "confirmed_remediated_roles": len(confirmed),
        "remaining_flagged_roles": sum(flagged(r) for r in right.values()),
        "finding_free_but_unverified_roles": len(missing_validation),
        "verified_reduction_percent": round(len(confirmed) / len(originally_flagged) * 100, 4),
        "scope": (
            "Observed scan counts with independently attested live AWS authorization checks; "
            "self-reported validation evidence still requires audit."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("validation", type=Path)
    args = parser.parse_args()
    print(json.dumps(measure(args.before, args.after, args.validation), indent=2))


if __name__ == "__main__":
    main()
