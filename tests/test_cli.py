import json

from aws_agent_identity_guard.cli import main


def test_static_sarif_output_writes_file(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "results.sarif"

    rc = main([str(policy), "--format", "sarif", "--output", str(output)])

    assert rc == 1
    assert output.exists()
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"]
