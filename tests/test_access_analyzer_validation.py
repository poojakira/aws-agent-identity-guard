from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from validation.aws_access_analyzer_pilot import compare_policy


class FakeAccessAnalyzer:
    def __init__(self) -> None:
        self.seen_policy_document = ""

    def validate_policy(self, *, policyDocument: str, policyType: str):
        self.seen_policy_document = policyDocument
        assert policyType == "IDENTITY_POLICY"
        return {
            "findings": [
                {
                    "findingType": "SECURITY_WARNING",
                    "issueCode": "PASS_ROLE_WITH_STAR_IN_RESOURCE",
                },
                {
                    "findingType": "WARNING",
                    "issueCode": "WILDCARD_USAGE_TOO_PERMISSIVE",
                },
            ]
        }


def test_differential_report_is_bound_to_exact_policy_bytes(tmp_path: Path):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
            }
        ],
    }
    raw = json.dumps(policy, indent=2).encode("utf-8")
    path = tmp_path / "agent-policy.json"
    path.write_bytes(raw)

    client = FakeAccessAnalyzer()
    report = compare_policy(client, path)

    assert report["policy"] == "agent-policy.json"
    assert report["policy_sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["local_finding_count"] > 0
    assert "AIG004" in report["local_rule_ids"]
    assert report["aws_finding_count"] == 2
    assert report["aws_finding_types"] == ["SECURITY_WARNING", "WARNING"]
    assert report["aws_issue_codes"] == [
        "PASS_ROLE_WITH_STAR_IN_RESOURCE",
        "WILDCARD_USAGE_TOO_PERMISSIVE",
    ]
    assert "effective permissions" in report["scope"]


def test_differential_adapter_sends_same_policy_semantics(tmp_path: Path):
    path = tmp_path / "scoped.json"
    path.write_text(
        json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": "arn:aws:bedrock:us-east-1::foundation-model/example",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    client = FakeAccessAnalyzer()
    compare_policy(client, path)
    sent = json.loads(client.seen_policy_document)
    assert sent["Statement"][0]["Action"] == "bedrock:InvokeModel"
