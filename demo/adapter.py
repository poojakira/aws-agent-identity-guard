import json

from aws_agent_identity_guard.studio.analysis import review_change

SPEC = {
    "title": "IAM Permission Engineering Studio",
    "version": "0.3.0",
    "description": "Run canonical identity-policy rules on labeled synthetic policies and "
    "compare an actual static-finding delta.",
    "scenarios": [
        {"id": "broad", "label": "Synthetic broad policy: Action * / Resource *"},
        {"id": "scoped", "label": "Synthetic scoped S3 object-read policy"},
        {"id": "compare", "label": "Review broad → scoped change with actual finding delta"},
    ],
    "limitations": [
        "Only bundled synthetic policies are used by this guided notebook. "
        "Use the local studio for your own policy.",
        "Static findings do not establish effective permissions, "
        "exploitability or deployment safety.",
        "No AWS call, account inventory, SCP/boundary/session/resource-policy "
        "intersection or live authorization.",
        "Comparison is a rule-fingerprint delta, not measured AWS risk reduction.",
    ],
    "repository": "https://github.com/poojakira/aws-agent-identity-guard/tree/codex/local-workbench-20261116",
}

BROAD = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
)
SCOPED = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::synthetic-demo/public/*",
            }
        ],
    }
)


def run(scenario):
    if scenario not in {item["id"] for item in SPEC["scenarios"]}:
        raise ValueError("Choose one of the documented synthetic scenarios")
    payload = {"policy": BROAD if scenario == "broad" else SCOPED}
    if scenario == "compare":
        payload["before_policy"] = BROAD
    result = review_change(payload)
    return {
        "summary": str(len(result["findings"]))
        + " static finding(s); effective permissions UNKNOWN; removed="
        + str(len(result["delta"]["removed"])),
        "engine_report": result,
    }
