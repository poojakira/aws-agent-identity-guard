"""Actual browser-to-engine acceptance, including uploads, deltas and SARIF schema."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from urllib.request import urlopen

from jsonschema import Draft4Validator, FormatChecker
from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--chromium", default="/usr/bin/chromium")
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    schema_bytes = Path(args.schema).read_bytes()
    expected_schema = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
    assert hashlib.sha256(schema_bytes).hexdigest() == expected_schema
    validator = Draft4Validator(json.loads(schema_bytes), format_checker=FormatChecker())
    process = subprocess.Popen(
        [sys.executable, "-m", "aws_agent_identity_guard.studio", "--port", "0"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        line = process.stdout.readline()
        if not line.startswith("IAM Permission Engineering Studio: http://127.0.0.1:"):
            raise RuntimeError("Local studio startup failed")
        base = line.strip().split()[-1]
        with urlopen(base + "/health", timeout=5) as response:
            health = json.load(response)
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=args.chromium, headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1100}, accept_downloads=True)
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(base)

            def review():
                page.get_by_role("button", name="Review IAM change", exact=True).click()
                expect(page.locator("#review")).to_be_enabled(timeout=15000)
                expect(page.locator("#json")).to_be_enabled()

            def export(button, filename):
                with page.expect_download() as download:
                    page.get_by_role("button", name=button, exact=True).click()
                download.value.save_as(output / filename)
                return output / filename

            page.get_by_role("button", name="Load synthetic example").click()
            review()
            first = json.loads(export("Export evidence JSON", "first-review.json").read_text())
            assert first["findings"] and first["effective_permissions"] == "UNKNOWN"
            assert first["source_commit"] == health["source_commit"]
            page.locator("#findings button").first.click()
            assert json.loads(page.locator("#evidence").inner_text())["Effect"] == "Allow"

            own = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "SyntheticUserUpload",
                        "Effect": "Allow",
                        "Action": "s3:ListBucket",
                        "Resource": "arn:aws:s3:::synthetic-user-bucket",
                    }
                ],
            }
            own_raw = json.dumps(own, indent=2)
            page.locator("#policy-file").set_input_files(
                {
                    "name": "user-policy.json",
                    "mimeType": "application/json",
                    "buffer": own_raw.encode(),
                }
            )
            expect(page.locator("#policy")).to_have_value(own_raw)
            expect(page.locator("#json")).to_be_disabled()
            assert page.locator("#location").inner_text() == "No current statement selected."
            review()
            second = json.loads(export("Export evidence JSON", "changed-review.json").read_text())
            assert second["sources"][0]["sha256"] == hashlib.sha256(own_raw.encode()).hexdigest()
            assert second["delta"]["comparison_performed"]
            assert (
                second["delta"]["removed"]
                and second["delta"]["after_count"] < second["delta"]["before_count"]
            )
            page.locator("#delta-findings button").filter(has_text="Before · removed").first.click()
            assert "Before:" in page.locator("#location").inner_text()
            sarif = json.loads(export("Export SARIF 2.1.0", "review.sarif").read_text())
            validator.validate(sarif)
            text = export("Export text review", "review.txt").read_text()
            assert second["run_id"] in text and "Effective permissions: UNKNOWN" in text

            trust = {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/<img src=x onerror=alert(1)>"
                    },
                }
            }
            page.locator("details summary").click()
            page.locator("#trust").fill(json.dumps(trust))
            review()
            assert page.locator("#graph img").count() == 0
            assert "<img" in page.locator("#graph").inner_text()
            trust_sarif = json.loads(
                export("Export SARIF 2.1.0", "identity-and-trust.sarif").read_text()
            )
            validator.validate(trust_sarif)
            assert len(trust_sarif["runs"]) == 2
            page.locator("#findings button").first.click()
            assert json.loads(page.locator("#evidence").inner_text())["Effect"] == "Allow"
            page.screenshot(path=str(output / "desktop.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            page.screenshot(path=str(output / "mobile.png"), full_page=True)

            def change_editor_before_real_response(route):
                actual_response = route.fetch()
                page.locator("#policy").fill(
                    json.dumps(
                        {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
                    )
                )
                route.fulfill(response=actual_response)

            # Delay the actual backend response while the operator changes input.
            # The response is not fabricated; its old input must not become current evidence.
            page.route("**/api/review", change_editor_before_real_response, times=1)
            page.get_by_role("button", name="Review IAM change", exact=True).click()
            expect(page.locator("#review")).to_be_enabled(timeout=15000)
            expect(page.locator("#json")).to_be_disabled()
            assert "changed during review" in page.locator("#status").inner_text()

            # Delay only the browser's actual File.text read. The review still
            # reaches the real backend while the previous editor text is visible.
            page.evaluate("""() => {
              window.originalFileText = File.prototype.text;
              window.pendingPolicyFiles = [];
              File.prototype.text = function() {
                return window.originalFileText.call(this).then(text =>
                  new Promise(resolve => {
                    window.pendingPolicyFiles.push(() => resolve(text));
                    document.documentElement.setAttribute('data-pending-policy-files',
                      String(window.pendingPolicyFiles.length));
                  }));
              };
            }""")
            uploaded_trust = json.dumps(
                {
                    "Statement": {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/Synthetic"},
                    }
                }
            )
            for input_id, editor_id, uploaded in [
                ("policy-file", "policy", own_raw),
                ("trust-file", "trust", uploaded_trust),
            ]:
                page.locator("#policy").fill(
                    json.dumps(
                        sample_policy := {
                            "Statement": [
                                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}
                            ]
                        }
                    )
                )
                page.locator("#trust").fill("")
                page.locator("#" + input_id).set_input_files(
                    {
                        "name": "delayed.json",
                        "mimeType": "application/json",
                        "buffer": uploaded.encode(),
                    }
                )
                expect(page.locator("html")).to_have_attribute("data-pending-policy-files", "1")
                review()
                expect(page.locator("#json")).to_be_enabled()
                page.evaluate("""() => {
                  window.pendingPolicyFiles.shift()();
                  document.documentElement.setAttribute('data-pending-policy-files', '0');
                }""")
                expect(page.locator("#" + editor_id)).to_have_value(uploaded)
                for export_id in ["json", "sarif", "human"]:
                    expect(page.locator("#" + export_id)).to_be_disabled()
                assert page.locator("#location").inner_text() == "No current statement selected."

                # A later edit must also supersede an earlier delayed file read.
                page.locator("#" + input_id).set_input_files(
                    {
                        "name": "obsolete.json",
                        "mimeType": "application/json",
                        "buffer": uploaded.encode(),
                    }
                )
                expect(page.locator("html")).to_have_attribute("data-pending-policy-files", "1")
                newer_text = json.dumps(sample_policy) if editor_id == "policy" else ""
                page.locator("#" + editor_id).fill(newer_text)
                page.evaluate("""() => {
                  window.pendingPolicyFiles.shift()();
                  document.documentElement.setAttribute('data-pending-policy-files', '0');
                }""")
                expect(page.locator("#" + editor_id)).to_have_value(newer_text)
                expect(page.locator("#json")).to_be_disabled()
            page.evaluate("() => { File.prototype.text = window.originalFileText; }")
            page.locator("#policy").fill('{"Statement":[3]}')
            page.get_by_role("button", name="Review IAM change", exact=True).click()
            expect(page.locator("#review")).to_be_enabled(timeout=15000)
            expect(page.locator("#json")).to_be_disabled()
            assert page.locator("#headline").inner_text() == "No analysis established"
            assert "non-object" in page.locator("#status").inner_text()
            assert not errors, errors
            browser.close()
        (output / "browser-result.json").write_text(
            json.dumps(
                {
                    "result": "passed",
                    "health": health,
                    "schema_sha256": expected_schema,
                    "checks": [
                        "real sample engine scan",
                        "source statement navigation",
                        "custom file upload",
                        "actual edit/rerun delta and before evidence",
                        "official SARIF schema for identity/trust exports",
                        "human review export",
                        "safe HTML-shaped principal rendering",
                        "mobile bounds",
                        "malformed input removes stale output",
                        "delayed real response is discarded after input changes",
                        "delayed identity/trust file completion invalidates real scan exports",
                        "later edits supersede obsolete asynchronous file reads",
                        "no browser errors",
                    ],
                },
                indent=2,
            )
        )
    finally:
        process.terminate()
        process.wait(timeout=10)


if __name__ == "__main__":
    main()
