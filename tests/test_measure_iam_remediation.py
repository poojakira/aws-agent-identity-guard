"""Tests for conservative IAM role remediation reporting."""

from __future__ import annotations

import json

import pytest

from scripts.measure_iam_role_remediation import measure


def reports(tmp_path):
    arn = "arn:aws:iam::123456789012:role/example"
    base = {
        "scan_complete": True,
        "errors": [],
        "roles_discovered": 1,
        "roles_scanned": 1,
        "account_id": "123456789012",
        "scan_timestamp": "2026-10-01T00:00:00Z",
    }
    before = dict(base, roles=[{"role_arn": arn, "high": 1, "critical": 0}])
    after = dict(
        base,
        scan_timestamp="2026-10-02T00:00:00Z",
        roles=[{"role_arn": arn, "high": 0, "critical": 0}],
    )
    a, b, v = [tmp_path / name for name in ("before.json", "after.json", "validation.json")]
    a.write_text(json.dumps(before))
    b.write_text(json.dumps(after))
    v.write_text(
        json.dumps(
            {
                arn: {
                    "authorization_verified": True,
                    "required_actions_verified": True,
                    "change_approved": True,
                    "evidence_ref": "change-ticket-123",
                    "environment": "live_aws",
                }
            }
        )
    )
    return a, b, v


def test_verified_reduction(tmp_path):
    a, b, v = reports(tmp_path)
    assert measure(a, b, v)["verified_reduction_percent"] == 100


def test_missing_authorization_blocks_credit(tmp_path):
    a, b, v = reports(tmp_path)
    v.write_text("{}")
    result = measure(a, b, v)
    assert result["verified_reduction_percent"] == 0
    assert result["finding_free_but_unverified_roles"] == 1


def test_incomplete_scan_rejected(tmp_path):
    a, b, v = reports(tmp_path)
    data = json.loads(b.read_text())
    data["scan_complete"] = False
    b.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="incomplete"):
        measure(a, b, v)


def test_changed_inventory_rejected(tmp_path):
    a, b, v = reports(tmp_path)
    data = json.loads(b.read_text())
    data["roles"][0]["role_arn"] = "arn:aws:iam::123456789012:role/other"
    b.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="inventories differ"):
        measure(a, b, v)
