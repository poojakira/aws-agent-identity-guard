"""Actual engine, source evidence, malformed inputs and loopback API boundaries."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import threading
from pathlib import Path

import pytest

from aws_agent_identity_guard.scanner import scan_policy_document, scan_trust_policy
from aws_agent_identity_guard.studio import __main__ as web
from aws_agent_identity_guard.studio.analysis import (
    Document,
    InputError,
    review_change,
    rule_inventory,
)


def policy(action="*", resource="*"):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}],
    }


def test_actual_engine_is_source_of_identity_and_trust_findings():
    identity = policy()
    trust = {"Statement": {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}}
    report = review_change({"policy": json.dumps(identity), "trust": json.dumps(trust)})
    expected = [f.rule_id for f in scan_policy_document(identity) + scan_trust_policy(trust)]
    assert [f["rule_id"] for f in report["findings"]] == expected
    assert "AIG-TP001" in expected
    assert report["effective_permissions"] == "UNKNOWN"
    assert len(rule_inventory()) == report["static_rule_count"] == 24
    assert report["live_context_rule_ids_not_run"] == ["AIG-PB001"]


def test_structural_source_location_is_not_confused_by_strings_or_single_statement():
    raw = (
        '{\n "Id": "Statement is just text here",\n "Statement": [\n  '
        '{"Sid":"example","Effect":"Allow","Action":"*","Resource":"*"}\n ]\n}'
    )
    report = review_change({"policy": raw})
    statement = next(f for f in report["findings"] if f["statement_index"] == 0)
    assert statement["location"]["startLine"] == statement["location"]["endLine"] == 4
    assert statement["location"]["json_pointer"] == "/Statement/0"
    assert json.loads(statement["location"]["snippet"])["Sid"] == "example"
    raw_single = json.dumps({"Statement": policy()["Statement"][0]}, indent=2)
    doc = Document(raw_single, "identity")
    assert doc.location(0)["json_pointer"] == "/Statement"
    assert doc.location(0)["startLine"] == 2


def test_policy_level_findings_do_not_invent_a_specific_statement_location():
    report = review_change({"policy": json.dumps(policy())})
    global_finding = next(f for f in report["findings"] if f["statement_index"] is None)
    assert global_finding["location"]["json_pointer"] == ""
    assert global_finding["location"]["startLine"] == 1


def test_edit_and_rerun_produces_actual_pattern_delta_and_complete_configuration():
    before = json.dumps(policy())
    after = json.dumps(policy("s3:GetObject", "arn:aws:s3:::synthetic-bucket/*"))
    original = review_change({"policy": before})
    report = review_change({"policy": after, "before_policy": before})
    assert report["delta"]["comparison_performed"]
    assert report["delta"]["before_count"] == len(original["findings"])
    assert len(report["delta"]["removed"]) > 0
    assert report["delta"]["after_count"] == len(report["findings"])
    assert report["configuration_sha256"] != original["configuration_sha256"]
    assert report["before_input_sha256"] == [hashlib.sha256(before.encode()).hexdigest()]


def test_deny_and_conditions_remain_visible_counter_evidence_not_false_effective_proof():
    document = policy("iam:PassRole")
    document["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalTag/team": "synthetic"}}
    document["Statement"].append({"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"})
    report = review_change({"policy": json.dumps(document)})
    finding = next(f for f in report["findings"] if f["rule_id"] == "AIG004")
    assert finding["counter_evidence"] == {
        "deny_statement_indices": [1],
        "conditions_present": True,
    }
    assert report["effective_permissions"] == "UNKNOWN"
    assert any(s["effect"] == "Deny" for s in report["statements"])
    assert any(edge.get("effect") == "Deny" for edge in report["graph"]["edges"])
    assert "Counter-evidence:" in report["human_report"]


def test_graph_only_contains_supported_supplied_context_and_marks_complements():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": ["s3:DeleteObject"],
                "NotResource": "arn:aws:s3:::protected/*",
            }
        ]
    }
    report = review_change({"policy": json.dumps(doc)})
    assert any(e["label"] == "NotAction exclusions" for e in report["graph"]["edges"])
    assert any(e["label"] == "NotResource exclusions" for e in report["graph"]["edges"])
    labels = " ".join(node["label"] for node in report["graph"]["nodes"])
    assert "s3:DeleteObject" in labels and "arn:aws:s3:::protected/*" in labels
    assert report["effective_permissions"] == "UNKNOWN"


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        "{}",
        '{"Statement":[1]}',
        '{"Statement":[]}',
        '{"Statement":{"Effect":"Allow","Action":"*","Action":"s3:GetObject","Resource":"*"}}',
        '{"Statement":{"Effect":"Allow","Action":5,"Resource":"*"}}',
        '{"Statement":{"Action":"*","Resource":"*"}}',
        '{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":[]}}',
        '{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Unknown":true}}',
        '{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"x":NaN}}}}',
        '{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"x":1e999}}}}',
        '{"Version":[],"Statement":{}}',
        "[" * 20 + "0" + "]" * 20,
    ],
)
def test_malformed_and_unsupported_inputs_fail_closed(raw):
    with pytest.raises(InputError):
        review_change({"policy": raw})


def test_byte_statement_string_and_configuration_bounds():
    for raw in [
        " " * 32769,
        json.dumps({"Statement": policy()["Statement"] * 33}),
        json.dumps(policy("a" * 4097)),
    ]:
        with pytest.raises(InputError):
            review_change({"policy": raw})
    for payload in [
        {"policy": json.dumps(policy()), "url": "http://127.0.0.1"},
        {"policy": {}},
        {"policy": json.dumps(policy()), "before_trust": "{}"},
    ]:
        with pytest.raises(InputError):
            review_change(payload)


def test_sarif_export_matches_official_schema_and_statement_line_evidence():
    schema_path = os.environ.get("SARIF_SCHEMA_PATH")
    if not schema_path:
        pytest.skip("Official SARIF schema not supplied; set SARIF_SCHEMA_PATH for the export gate")
    from jsonschema import Draft4Validator, FormatChecker

    schema_bytes = Path(schema_path).read_bytes()
    assert (
        hashlib.sha256(schema_bytes).hexdigest()
        == "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
    )
    report = review_change({"policy": json.dumps(policy(), indent=2)})
    Draft4Validator(json.loads(schema_bytes), format_checker=FormatChecker()).validate(
        report["sarif"]
    )
    assert all(
        r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        for r in report["sarif"]["runs"][0]["results"]
    )


def test_http_boundaries_actual_engine_error_recovery_and_rate(monkeypatch):
    server = web.create_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def post(payload=None, headers=None, raw=None):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request(
            "POST",
            "/api/review",
            body=raw
            if raw is not None
            else json.dumps(payload or {"policy": json.dumps(policy())}),
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        response = connection.getresponse()
        status, data = response.status, json.loads(response.read())
        connection.close()
        return status, data

    try:
        assert post(headers={"Origin": "https://untrusted.example"})[0] == 403
        assert post(headers={"Host": "untrusted.example"})[0] == 403
        assert post(headers={"Content-Type": "text/plain"})[0] == 415
        assert post(raw="x" * 196609)[0] == 413
        assert post(raw='{"policy":"{}","policy":"{}"}')[0] == 400
        assert post(raw="[" * 1000 + "0" + "]" * 1000)[0] == 400
        status, report = post()
        assert status == 200 and len(report["findings"]) > 0
        original = web.review_change

        def crash(_payload):
            raise RuntimeError("synthetic sensitive exception text")

        monkeypatch.setattr(web, "review_change", crash)
        status, response = post()
        assert status == 500 and "synthetic sensitive" not in json.dumps(response)
        monkeypatch.setattr(web, "review_change", original)
        assert post()[0] == 200
        for _ in range(30):
            status, _ = post()
            if status == 429:
                break
        assert status == 429
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
