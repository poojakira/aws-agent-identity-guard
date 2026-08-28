# Security Audit — aws-agent-identity-guard

**Auditor:** agent/security-hardening-v1 (automated)
**Date:** 2026-08-05
**Commit base:** main (cloned fresh)
**Files audited:** `src/aws_agent_identity_guard/scanner.py`, `cli.py`, `tests/test_scanner.py`, `pyproject.toml`, `.github/workflows/ci.yml`

---

## Summary

The tool is a pure-Python static linter with no external dependencies and no runtime AWS credential usage. The attack surface is narrow: it reads a local JSON file and emits text or JSON. The main risk vectors are (1) gaps in rule coverage, (2) CI pipeline supply-chain risks, and (3) missing output format coverage that keeps the tool from integrating into SAST pipelines (SARIF).

Overall posture before this hardening: **moderate**. No critical code vulnerabilities were found, but trust-policy rules were absent and CI actions were unpinned.

---

## Findings Before This PR

### SEC-01 · HIGH — Trust-policy rules absent

`scan_policy_document` inspects permission-policy documents only. IAM roles for agents are also exploitable via their *trust policies* (who can assume the role). Three high-value trust-policy anti-patterns were not checked:

| Anti-pattern | Impact |
|---|---|
| `Principal: "*"` (wildcard) | Any AWS principal — or anonymous — can assume the role |
| Cross-account trust with no `sts:ExternalId` condition | Classic confused-deputy / supply-chain pivot |
| Cross-account trust with no `aws:SourceArn` condition | Allows lateral movement from any resource in the trusted account |

**Status:** Fixed in this PR — `scan_trust_policy()` added (rules AIG-TP001–AIG-TP003).

---

### SEC-02 · HIGH — CI actions not pinned to commit SHAs

`ci.yml` used floating tags (`actions/checkout@v4`, `actions/setup-python@v5`, `actions/upload-artifact@v4`). A compromised tag can redirect to malicious code with no diff visible in the workflow file.

**Status:** Fixed in this PR — all three actions pinned to their current commit SHAs.

---

### SEC-03 · MEDIUM — SARIF output format missing

The tool only emits `text` and `json` output. GitHub Code Scanning (GHAS) and many SAST aggregators ingest SARIF 2.1.0. Without it, findings are invisible to security dashboards.

**Status:** Fixed in this PR — `--format sarif` added, schema-compliant SARIF 2.1.0 emitted.

---

### SEC-04 · LOW — `bandit` run scope in CI was limited to a subdirectory

The `security` job ran `bandit -r src/ -ll`. This is correct for the existing code; no change needed. Confirmed: no bandit findings in the codebase (no `subprocess`, `eval`, `exec`, `pickle`, `yaml.load`, `tempfile` without `mkstemp`, or shell-injection patterns present).

**Status:** No change needed. Noted for record.

---

### SEC-05 · INFO — No test coverage gate

`pyproject.toml` and `ci.yml` do not enforce a minimum coverage percentage. This is a risk as the codebase grows.

**Status:** Out of scope for this PR (would require adding `pytest-cov` dependency). Noted.

---

### SEC-06 · INFO — `_load_json` raises `SystemExit` on malformed input

`cli.py::_load_json` calls `raise SystemExit(...)` directly rather than returning a structured error. This is acceptable for a CLI tool but means callers of the scanner library cannot distinguish "bad input" from "policy has findings". The `scan_policy_document` function itself does not validate that the input is a real IAM policy document.

**Status:** `scan_trust_policy` in this PR validates the `Principal` field structure explicitly rather than silently ignoring malformed input.

---

## What Was Not Changed

- Core `scan_policy_document` logic — no regressions introduced.
- `pyproject.toml` dependencies — no new runtime dependencies added.
- Existing tests — only new tests added; no existing tests modified.
- Exit-code logic — unchanged; exit 1 on any high/critical finding.

---

## New Rules Added (this PR)

| Rule ID | Severity | Description |
|---|---|---|
| AIG-TP001 | CRITICAL | Trust policy has wildcard Principal (`"*"`) |
| AIG-TP002 | HIGH | Cross-account trust statement missing `sts:ExternalId` condition |
| AIG-TP003 | HIGH | Cross-account trust statement missing `aws:SourceArn` condition |

---

## Verification

```bash
# Run full test suite (must pass 100%)
pip install -e ".[dev]"
pytest tests/ -v

# Lint
ruff check src tests
ruff format --check src tests

# Static security scan
bandit -r src/ -ll
```
