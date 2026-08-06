# Threat Model — AWS Agent Identity Guard

**Version:** 0.1.0  
**Method:** STRIDE  
**Scope:** Static linter CLI + optional live Boto3 scanning mode  
**Last updated:** 2026-08-06

---

## 1. System Description

`aws-agent-identity-guard` is a Python CLI tool that:

1. **Static mode** — Reads local IAM policy JSON files and flags over-privileged patterns.
2. **Live mode** — Enumerates IAM roles and users in a live AWS account via Boto3 and runs the same rules against each collected policy document.

### Data Flow

```
[IAM policy JSON file]
        │
        ▼
[CLI: argparse → json.loads]
        │
        ▼
[scanner.py: scan_policy_document / scan_trust_policy]
        │
        ▼
[Output: text / JSON / SARIF to stdout or file]

[Live mode only]
[AWS IAM APIs (read-only)] → [live_scanner.py: boto3] → same rule engine above
```

### Trust Boundaries

| Boundary | Description |
|----------|-------------|
| **File system** | Tool reads one JSON file from disk. No write access needed. |
| **AWS IAM API** | Live mode reads IAM metadata. No write or mutate calls. |
| **CI pipeline** | Tool is invoked as a build step; output (SARIF) is uploaded as an artifact. |
| **Operator** | Person running the tool or configuring CI. |

---

## 2. Assets

| Asset | Sensitivity | Location |
|-------|------------|----------|
| IAM policy documents | Medium — may reveal resource ARN patterns | Input file / in-memory only |
| AWS account ID | Low — exposed in role ARNs in live scan output | Scan report JSON |
| IAM role and user names | Low | Scan report JSON |
| AWS credentials (live mode) | Critical | Operator environment — **not stored by the tool** |
| SARIF output file | Low | Written to disk only if `--output` flag used |

---

## 3. Threat Analysis (STRIDE)

### S — Spoofing

| Threat | Mitigated? | Notes |
|--------|-----------|-------|
| Attacker supplies a crafted policy JSON that causes the tool to misreport severity | Partially | JSON parsing uses stdlib `json.loads`; no eval or exec paths. Malformed JSON raises `json.JSONDecodeError` and the tool exits 2. |
| Attacker replaces the policy file between tool invocation and read | Accepted risk | TOCTOU on file read. Operator must ensure the file is the one they intend to scan. |

### T — Tampering

| Threat | Mitigated? | Notes |
|--------|-----------|-------|
| Attacker modifies SARIF output after generation | Accepted risk | Output is written once; integrity is the responsibility of the CI pipeline (artifact checksums). |
| Supply-chain compromise of GitHub Actions | Mitigated | All actions pinned to commit SHAs. |
| Dependency substitution attack | Mitigated | `pip-audit` runs in CI. No runtime deps in static mode. |

### R — Repudiation

| Threat | Mitigated? | Notes |
|--------|-----------|-------|
| Operator denies that a policy was scanned | Accepted risk | Tool does not maintain its own audit log. CI artifacts serve as evidence. |

### I — Information Disclosure

| Threat | Mitigated? | Notes |
|--------|-----------|-------|
| Scan report leaks sensitive resource ARNs | Mitigated | ARNs from live mode are included in findings for remediation context, not exfiltrated. Operator controls where reports are stored. |
| AWS credentials in tool output | Mitigated | Tool never logs or outputs credentials. Boto3 credential chain sources are not echoed. |

### D — Denial of Service

| Threat | Mitigated? | Notes |
|--------|-----------|-------|
| Very large policy document exhausts memory | Partially | No explicit file-size limit. Practical risk is low (IAM policies are capped at 6 KB by AWS). |
| Live scan enumerates excessive roles | Mitigated | `max_roles=500` safety cap in `LiveAccountScanner`. |
| AWS API throttling during live scan | Handled | Boto3 retries with exponential backoff by default. `ClientError` exceptions are caught and logged; scan continues. |

### E — Elevation of Privilege

| Threat | Mitigated? | Notes |
|--------|-----------|-------|
| Live scanner mutates IAM resources | Mitigated | No write IAM APIs are called. Minimum required permissions are all read-only (`iam:List*`, `iam:Get*`, `sts:GetCallerIdentity`). |
| Scanner identity used for privilege escalation | Mitigated | The recommended scanner IAM policy (in README) contains no privilege-escalation actions. |

---

## 4. Security Assumptions

1. The operator running the tool controls the input file path.
2. In live mode, the operator has consciously configured AWS credentials with the read-only policy documented in the README.
3. CI artifacts (SARIF output) are stored with appropriate access controls by the pipeline.
4. The Python interpreter and OS running the tool are not compromised.

---

## 5. Out-of-Scope Threats

- Physical access to the machine running the tool
- Compromise of the AWS account itself (that is what this tool helps detect, not prevent)
- Side-channel attacks on the analysis algorithm
- Bypass of IAM authorization for the scanner identity by a privileged attacker in the account

---

## 6. Residual Risks

| Risk | Likelihood | Impact | Accepted / Mitigate |
|------|-----------|--------|-------------------|
| False negatives (undetected over-privileged policies) | Medium | High | **Accepted** — tool is a best-effort linter, not a complete IAM semantics engine. Use IAM Access Analyzer for complete analysis. |
| SARIF output not reviewed | Medium | Medium | **Accepted** — operator responsibility. |
| Live scan credentials leaked through process listing | Low | High | **Accepted** — standard credential hygiene. |
