from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from validation.aws_access_analyzer_pilot import _aws_validate, compare_policy


class FakeAccessAnalyzer:
    def __init__(self, findings):
        self.findings = findings
        self.calls = []

    def validate_policy(self, **kwargs):
        self.calls.append(kwargs)
        return {"findings": self.findings}


def test_aws_validate_uses_identity_policy_and_compact_json():
    client = FakeAccessAnalyzer([{"findingType": "SECURITY_WARNING"}])
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }

    findings = _aws_validate(client, policy)

    assert findings == [{"findingType": "SECURITY_WARNING"}]
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["policyType"] == "IDENTITY_POLICY"
    assert json.loads(call["policyDocument"]) == policy


def test_compare_policy_keeps_local_and_aws_evidence_separate(tmp_path: Path):
    policy_path = tmp_path / "agent-role.json"
    policy_path.write_text(
        json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                ],
            }
        ),
        encoding="utf-8",
    )
    client = FakeAccessAnalyzer(
        [
            {"findingType": "SECURITY_WARNING"},
            {"findingType": "ERROR"},
            {"findingType": "SECURITY_WARNING"},
        ]
    )

    result = compare_policy(client, policy_path)

    assert result["policy"] == "agent-role.json"
    assert result["local_finding_count"] > 0
    assert "AIG002" in result["local_rule_ids"]
    assert result["aws_finding_count"] == 3
    assert result["aws_finding_types"] == ["ERROR", "SECURITY_WARNING"]
    assert "neither side computes" in result["scope"].lower()


def test_aws_validate_handles_non_list_findings_defensively():
    class BadShapeClient:
        def validate_policy(self, **kwargs):
            return {"findings": {"unexpected": True}}

    assert _aws_validate(BadShapeClient(), {"Version": "2012-10-17", "Statement": []}) == []
