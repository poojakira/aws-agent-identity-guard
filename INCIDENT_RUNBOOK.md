# Incident Response Runbook — aws-agent-identity-guard

This runbook covers operational incidents related to the IAM identity guard tool in CI/CD pipelines and live scanning environments.

---

## Table of Contents

1. [False Positive in Production CI Gate](#1-false-positive-in-production-ci-gate)
2. [New Privilege Escalation Pattern Discovered](#2-new-privilege-escalation-pattern-discovered)
3. [Live Scanner Rate Limiting by AWS](#3-live-scanner-rate-limiting-by-aws)
4. [Misleading Remediation Suggestion](#4-misleading-remediation-suggestion)

---

## 1. False Positive in Production CI Gate

### Symptoms

- CI pipeline blocks a deployment with a finding that the team believes is incorrect.
- The flagged policy has been in production without issues.
- The finding references a rule that does not apply given the context (e.g., conditions restrict access).

### Severity

**Medium** — Blocks deployment velocity but no security impact.

### Immediate Response (< 15 minutes)

1. **Identify the blocking rule:**
   ```bash
   # Check CI logs for the specific finding
   grep -A5 "FAIL\|CRITICAL\|HIGH" ci-output.log
   ```

2. **Verify it's a false positive:**
   - Check if the policy has `Condition` blocks that limit scope.
   - Check if `Resource` is narrowed despite a broad `Action`.
   - Check if it's a Deny statement being incorrectly evaluated.

3. **Temporary bypass (if deployment is urgent):**

   The scanner has no suppression flag. To unblock an urgent deploy, gate the
   scan step in CI behind a manual approval, or run the scan in a non-blocking
   (advisory) job so the exit code does not fail the pipeline. Re-enable the
   blocking gate as soon as the finding is triaged.

4. **Document the bypass** in your team's incident channel with:
   - The policy ARN or file path
   - The rule ID that fired
   - Why it's a false positive
   - Who approved the bypass

### Root Cause Investigation (< 4 hours)

1. **Reproduce locally:**
   ```bash
   aws-agent-identity-guard ./the-policy.json --format json
   ```

2. **Check rule logic:**
   - Review the rule logic inline in `src/aws_agent_identity_guard/scanner.py`
     (rules are implemented in `scan_policy_document()` / `scan_trust_policy()`
     with IDs like `AIG002`; there is no separate `rules/` directory).
   - Determine if the rule accounts for Condition blocks
   - Check if the rule handles `NotAction`/`NotResource` correctly

3. **File a bug or contribute a fix:**
   ```bash
   # Create a test case that captures the false positive
   # Add to tests/test_false_positives.py
   pytest tests/test_false_positives.py -v
   ```

### Resolution

- **If rule logic is wrong:** Submit PR with fix + regression test.
- **If rule is too broad:** Add condition-aware narrowing to the rule.
- **If policy is unusual:** Add to known-safe patterns allowlist.

### Prevention

- Add the false-positive case to the test suite.
- Consider adding a `--strict` vs `--advisory` mode split.
- Review rule precision metrics quarterly.

---

## 2. New Privilege Escalation Pattern Discovered

### Symptoms

- Security research (internal or external) identifies a new IAM privilege escalation path.
- The current rule set (25 rules) does not detect this pattern.
- Existing policies in production may be vulnerable.

### Severity

**High** — Potential security gap.

### Immediate Response (< 1 hour)

1. **Assess exposure:**
   ```bash
   # Scan all roles in the account/region for the new pattern
   AWS_PROFILE=prod-readonly aws-agent-identity-guard --live-scan --format json | grep -i "PassRole\|CreatePolicy\|AssumeRole"
   ```

2. **Document the escalation path:**
   - What permissions are required?
   - What is the escalation outcome (admin, data access, lateral movement)?
   - Is there a public CVE or blog post?

3. **Notify the security team** via your incident management system.

### Developing the New Rule (< 24 hours)

1. **Add the rule logic:**
   ```python
   # src/aws_agent_identity_guard/scanner.py
   # Rules are implemented inline inside scan_policy_document() (or
   # scan_trust_policy() for trust-policy checks). Add a new check with the
   # next available AIG ID, e.g. AIG022:
   #
   #   findings.append(Finding(
   #       rule_id="AIG022",
   #       severity="CRITICAL",
   #       message="Detects <technique> privilege escalation pattern",
   #       ...
   #   ))
   ```

2. **Add test cases:**
   ```python
   # tests/test_scanner.py
   def test_detects_new_escalation():
       document = { ... }  # The vulnerable pattern
       findings = scan_policy_document(document)
       assert any(f["rule_id"] == "AIG022" for f in findings)

   def test_no_false_positive_on_safe_variant():
       document = { ... }  # Similar but safe pattern
       findings = scan_policy_document(document)
       assert not any(f["rule_id"] == "AIG022" for f in findings)
   ```

3. **Run the full test suite:**
   ```bash
   pytest tests/ -v
   ```

4. **Release a patch version immediately:**
   ```bash
   git tag v0.3.1
   git push origin v0.3.1  # Triggers signed release workflow
   ```

### Post-Incident

- Update `CHANGELOG.md` with security advisory.
- Notify downstream users via GitHub Security Advisory if needed.
- Retrospective: Why wasn't this pattern caught earlier?

---

## 3. Live Scanner Rate Limiting by AWS

### Symptoms

- Live scanner (`--live` mode) starts receiving `ThrottlingException` or `RateLimitExceeded` errors.
- Scans take significantly longer than baseline.
- Incomplete scan results (some policies not evaluated).

### Severity

**Medium** — Scan coverage is degraded but no security regression.

### Immediate Response (< 15 minutes)

1. **Confirm throttling:**
   ```bash
   # Check for throttling errors in output
   AWS_PROFILE=prod-readonly aws-agent-identity-guard --live-scan --format json 2>&1 | grep -i "throttl\|rate"
   ```

2. **Check AWS Service Health Dashboard** for IAM API issues.

3. **Scope the scan to reduce API volume:**
   ```bash
   # Scan a single role instead of the whole account
   aws-agent-identity-guard --live-scan --role-name my-agent-role --format json
   ```

### Mitigation (< 1 hour)

1. **Enable exponential backoff** (should be default, verify):
   ```python
   # boto3 config
   from botocore.config import Config
   config = Config(
       retries={"max_attempts": 10, "mode": "adaptive"}
   )
   ```

2. **Reduce API call volume:**
   - Use `--role-name` to scan one role at a time instead of the whole account.
   - Scan exported policy JSON files statically instead of live where possible.
   - Space out live scans rather than running them back-to-back.

3. **Switch to static/offline mode temporarily:**
   ```bash
   # Save role/policy documents to JSON via the AWS CLI, then scan them statically
   aws iam get-role-policy --role-name my-role --policy-name inline > policy.json
   aws-agent-identity-guard policy.json --format json
   ```

### Long-term Fixes

- Implement delta scanning (only re-scan changed policies).
- Use AWS Config rules or EventBridge to trigger scans on policy changes.
- Request IAM API limit increase via AWS Support if sustained scanning is needed.
- Add CloudWatch metrics for API call budget tracking.

### Monitoring

```bash
# Add to your monitoring
aws cloudwatch get-metric-statistics \
  --namespace AWS/IAM \
  --metric-name ThrottledRequests \
  --period 300 \
  --statistics Sum \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S)
```

---

## 4. Misleading Remediation Suggestion

### Symptoms

- A `--remediate` suggestion is misleading, incomplete, or wrong for a finding.
- A team member misreads a suggestion as an executable script and tries to apply it.
- The suggested action does not actually resolve the flagged rule.

### Severity

**Medium** — `--remediate` only prints human-readable suggestions to stdout; it
does not generate or apply infrastructure code. The risk is a human acting on a
misleading suggestion, not the tool mutating infrastructure.

### Immediate Response (< 30 minutes)

1. **Clarify what `--remediate` does:**
   ```bash
   # --remediate appends text remediation guidance to the findings output.
   # It does NOT write Terraform, and it does NOT apply any changes.
   aws-agent-identity-guard policy.json --remediate
   ```
   Ensure no downstream job treats this text output as an applyable artifact.

2. **Notify teams** that may have acted on a misleading suggestion.

### Diagnosis

1. **Reproduce the suggestion locally:**
   ```bash
   aws-agent-identity-guard failing-policy.json --remediate --format text
   ```

2. **Common issues:**

   | Symptom | Likely Cause | Fix |
   |---------|-------------|-----|
   | Suggestion too generic | Rule emits a static remediation string | Tighten the message in `scanner.py` |
   | Suggestion doesn't match finding | Wrong branch in the remediation text | Correct the per-rule message in `scanner.py` |
   | Missing remediation text | Rule has no remediation guidance | Add guidance to the rule in `scanner.py` |

3. **Check the remediation text:**
   ```bash
   # Remediation strings are defined inline alongside the rules in scanner.py
   grep -n "REMEDIATION" src/aws_agent_identity_guard/scanner.py
   ```

### Resolution

1. **Fix the remediation message** in `src/aws_agent_identity_guard/scanner.py`
   next to the rule that emits it.

2. **Add a regression test:**
   ```python
   # tests/test_scanner.py
   def test_remediation_text_present_for_finding():
       document = { ... }
       findings = scan_policy_document(document)
       assert findings  # at least one finding
       # --remediate output is rendered by the CLI from these findings
   ```

### Prevention

- Keep remediation strings specific and tied to the exact rule that fires.
- Add tests that assert findings are produced for known-bad fixtures.
- Make clear in docs that `--remediate` output is advisory text, not runnable code.

---

## General Escalation Path

| Level | Contact | When |
|-------|---------|------|
| L1 | On-call engineer | Any incident during business hours |
| L2 | Security team lead | Privilege escalation gaps, active exploitation |
| L3 | CISO / VP Engineering | Data breach, widespread CI outage |

## Post-Incident Template

```markdown
## Incident Summary
- **Date:** YYYY-MM-DD
- **Duration:** X hours
- **Severity:** Low / Medium / High / Critical
- **Impact:** [Who/what was affected]

## Timeline
- HH:MM — [Event]
- HH:MM — [Response action]

## Root Cause
[Technical explanation]

## Resolution
[What fixed it]

## Action Items
- [ ] [Preventive measure 1]
- [ ] [Preventive measure 2]
```
