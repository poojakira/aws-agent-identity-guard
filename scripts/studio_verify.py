"""Generate fresh out-of-tree evidence from actual executable local checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--chromium", default="/usr/bin/chromium")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = Path(args.output).resolve()
    if output == root or root in output.parents:
        raise ValueError("Evidence must be written outside the source checkout")
    output.mkdir(parents=True, exist_ok=True)

    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=root, text=True).strip()

    if git("status", "--porcelain"):
        raise RuntimeError("Freeze a clean source candidate before generating final evidence")

    def now():
        return datetime.now(timezone.utc).isoformat()

    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    manifest = {
        "repository": "poojakira/aws-agent-identity-guard",
        "source_commit": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "clean_before": True,
        "utc_start": now(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "run_id": os.environ.get("GITHUB_RUN_ID") or "local-" + now(),
        "version": "0.3.0",
        "static_rule_count": 24,
        "additional_live_context_rule_count": 1,
        "test_environment_pins_sha256": sha(root / "requirements-studio-test.txt"),
        "official_schema_sha256": sha(Path(args.schema)),
        "decision": "PARTIAL",
        "runs": [],
        "limitations": [
            "Static patterns do not establish effective IAM permissions or exploitability",
            "No live AWS validation; actual skip names and reasons are recorded separately",
            "No public or multi-user deployment approval",
            "Full historical document and branch reconciliation remains incomplete",
            "Installed wheels cannot attest to source Git metadata and report UNKNOWN",
        ],
    }
    python = sys.executable
    cache = output.parent / ("iam-studio-tool-cache-" + manifest["source_commit"][:12])
    env = {
        **os.environ,
        "PYTHONPATH": str(root / "src"),
        "COVERAGE_FILE": str(output / "coverage-data"),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "SARIF_SCHEMA_PATH": str(Path(args.schema).resolve()),
        "XDG_CACHE_HOME": str(cache),
        "npm_config_cache": str(cache / "npm"),
    }
    commands = [
        ("dependencies", [python, "-m", "pip", "freeze", "--all"]),
        ("lint", [python, "-m", "ruff", "check", "."]),
        ("format", [python, "-m", "ruff", "format", "--check", "."]),
        (
            "regression",
            [
                python,
                "-m",
                "pytest",
                "-p",
                "pytest_cov",
                "tests/",
                "-q",
                "--cov=aws_agent_identity_guard",
                "--cov-report=json:" + str(output / "coverage.json"),
                "--cov-report=term-missing",
                "--junitxml=" + str(output / "junit.xml"),
            ],
        ),
        (
            "typecheck_studio",
            [
                python,
                "-m",
                "pyright",
                "--pythonpath",
                python,
                "src/aws_agent_identity_guard/studio",
            ],
        ),
        (
            "bandit",
            [
                python,
                "-m",
                "bandit",
                "-r",
                "src",
                "-ll",
                "-f",
                "json",
                "-o",
                str(output / "bandit.json"),
            ],
        ),
        (
            "browser",
            [
                python,
                "scripts/studio_e2e.py",
                "--output",
                str(output / "browser"),
                "--schema",
                args.schema,
                "--chromium",
                args.chromium,
            ],
        ),
        ("build", [python, "-m", "build", "--outdir", str(output / "artifacts")]),
        (
            "dependency_audit",
            [
                python,
                "-m",
                "pip_audit",
                "--skip-editable",
                "--cache-dir",
                str(cache / "pip-audit"),
                "--format",
                "json",
                "--output",
                str(output / "pip-audit.json"),
            ],
        ),
        (
            "performance_existing_gate",
            [
                python,
                "benchmarks/perf_gate.py",
                "--policies",
                "500",
                "--output",
                str(output / "performance.json"),
            ],
        ),
    ]
    failed = False
    for label, command in commands:
        start = now()
        try:
            result = subprocess.run(
                command, cwd=root, env=env, capture_output=True, text=True, timeout=180
            )
            code, log = result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            code, log = 124, "Check exceeded the 180-second verification timeout"
        (output / (label + ".log")).write_text(log)
        manifest["runs"].append(
            {
                "name": label,
                "command": command,
                "utc_start": start,
                "utc_end": now(),
                "exit_code": code,
                "log": label + ".log",
            }
        )
        failed |= code != 0
        print(label, code, flush=True)
    if (output / "junit.xml").exists():
        suites = list(ElementTree.parse(output / "junit.xml").getroot().iter("testsuite"))
        manifest["tests"] = {
            key: sum(int(suite.get(key, "0")) for suite in suites)
            for key in ("tests", "failures", "errors", "skipped")
        }
        manifest["tests"]["passed"] = (
            manifest["tests"]["tests"]
            - manifest["tests"]["failures"]
            - manifest["tests"]["errors"]
            - manifest["tests"]["skipped"]
        )
        manifest["skipped_tests"] = [
            {
                "name": case.get("name"),
                "class": case.get("classname"),
                "reason": skipped.get("message", ""),
            }
            for case in ElementTree.parse(output / "junit.xml").getroot().iter("testcase")
            for skipped in case.findall("skipped")
        ]
        if manifest["tests"]["tests"] < 200:
            failed = True
            manifest["test_collection_gate"] = "FAILED: existing minimum200 test collection gate"
    if (output / "coverage.json").exists():
        manifest["coverage"] = json.loads((output / "coverage.json").read_text())["totals"]
    manifest["clean_after"] = not bool(git("status", "--porcelain"))
    manifest["utc_end"] = now()
    manifest["checks_passed"] = not failed and manifest["clean_after"]
    manifest["artifacts"] = {
        str(path.relative_to(output)): sha(path)
        for path in output.rglob("*")
        if path.is_file()
        and path.name != "manifest.json"
        and "cache" not in path.relative_to(output).parts
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
    raise SystemExit(1 if failed or not manifest["clean_after"] else 0)


if __name__ == "__main__":
    main()
