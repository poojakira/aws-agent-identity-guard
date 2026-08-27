# Incident Response Runbook — aws-agent-identity-guard

This runbook covers operational incidents related to the IAM identity guard tool in CI/CD pipelines and live scanning environments.

---

## Table of Contents

1. [False Positive in Production CI Gate](#1-false-positive-in-production-ci-gate)
2. [New Privilege Escalation Pattern Discovered](#2-new-privilege-escalation-pattern-discovered)
3. [Live Scanner Rate Limiting by AWS](#3-live-scanner-rate-limiting-by-aws)
4. [Remediation Template Generates Broken Terraform](#4-remediation-template-generates-broken-terraform)

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
   ```yaml
   # Add inline suppression to the policy annotation
   # In your CI config:
   identity-guard scan --suppress RULE-ID --reason "FP: conditions restrict to org only"
   ```

   Or set the environment variable:
   ```bash
   export IDENTITY_GUARD_SUPPRESS="RULE-042,RULE-017"
   ```

4. **Document the bypass** in your team's incident channel with:
   - The policy ARN or file path
   - The rule ID that fired
   - Why it's a false positive
   - Who approved the bypass

### Root Cause Investigation (< 4 hours)

1. **Reproduce locally:**
   ```bash
   identity-guard scan --policy-file ./the-policy.json --verbose
   ```

2. **Check rule logic:**
   - Review the rule definition in `src/aws_agent_identity_guard/rules/`
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
   # Scan all policies for the new pattern manually
   identity-guard scan --live --profile prod-readonly | grep -i "PassRole\|CreatePolicy\|AssumeRole"
   ```

2. **Document the escalation path:**
   - What permissions are required?
   - What is the escalation outcome (admin, data access, lateral movement)?
   - Is there a public CVE or blog post?

3. **Notify the security team** via your incident management system.

### Developing the New Rule (< 24 hours)

1. **Create the rule definition:**
   ```python
   # src/aws_agent_identity_guard/rules/new_rule.py
   RULE = {
       "id": "RULE-026",
       "name": "privilege-escalation-via-<technique>",
       "severity": "CRITICAL",
       "description": "Detects <technique> privilege escalation pattern",
       "actions": ["iam:<action1>", "iam:<action2>"],
       "condition": "all_present",  # or "any_present"
       "resource": "*",
   }
   ```

2. **Add test cases:**
   ```python
   # tests/test_new_escalation.py
   def test_detects_new_escalation():
       policy = { ... }  # The vulnerable pattern
       findings = scan_policy(policy)
       assert any(f["rule_id"] == "RULE-026" for f in findings)

   def test_no_false_positive_on_safe_variant():
       policy = { ... }  # Similar but safe pattern
       findings = scan_policy(policy)
       assert not any(f["rule_id"] == "RULE-026" for f in findings)
   ```

3. **Run the full test suite:**
   ```bash
   pytest --cov --cov-fail-under=90
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
   identity-guard scan --live --profile prod-readonly 2>&1 | grep -i "throttl\|rate"
   ```

2. **Check AWS Service Health Dashboard** for IAM API issues.

3. **Reduce scan parallelism:**
   ```bash
   # Lower concurrency
   identity-guard scan --live --max-concurrent 2 --retry-delay 5
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
   - Use `--scope` to limit to specific accounts/OUs.
   - Cache policy documents that haven't changed (check `UpdateDate`).
   - Use `iam:GetAccountAuthorizationDetails` instead of per-policy calls.

3. **Switch to cached/offline mode temporarily:**
   ```bash
   # Export policies first, then scan locally
   identity-guard export --live --output policies/
   identity-guard scan --policy-dir policies/
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

## 4. Remediation Template Generates Broken Terraform

### Symptoms

- Auto-generated remediation Terraform fails `terraform plan` or `terraform apply`.
- Syntax errors, invalid resource references, or incompatible provider versions.
- Teams apply remediation and break their infrastructure.

### Severity

**High** — Can cause production infrastructure issues if applied without review.

### Immediate Response (< 30 minutes)

1. **Stop automated remediation pipelines:**
   ```bash
   # Disable auto-apply in CI if configured
   # Set environment variable to block auto-remediation
   export IDENTITY_GUARD_REMEDIATE=dry-run
   ```

2. **Identify affected outputs:**
   ```bash
   # Check recently generated remediations
   find ./remediation-output/ -name "*.tf" -newer /tmp/last-known-good -exec terraform validate {} \;
   ```

3. **Notify teams** that have recently applied generated Terraform.

### Diagnosis

1. **Validate the template locally:**
   ```bash
   # Generate remediation for the failing policy
   identity-guard remediate --policy-file failing-policy.json --output /tmp/fix.tf

   # Validate
   cd /tmp && terraform init && terraform validate
   ```

2. **Common issues:**

   | Symptom | Likely Cause | Fix |
   |---------|-------------|-----|
   | `Invalid resource type` | Wrong AWS provider version assumed | Pin provider version in template |
   | `Reference to undeclared resource` | Template references resources not in state | Add data sources or variables |
   | `Invalid argument` | API changed, argument renamed/removed | Update template to current provider schema |
   | `Cycle detected` | Circular dependency in generated resources | Restructure resource ordering |
   | HCL syntax error | Template engine bug | Fix Jinja/string formatting in remediate.py |

3. **Check the template engine:**
   ```bash
   # Review remediate.py for the failing pattern
   grep -n "def generate" src/aws_agent_identity_guard/remediate.py
   ```

### Resolution

1. **Fix the template:**
   ```python
   # Common fix: ensure provider compatibility
   # In remediate.py, add provider version constraint
   PROVIDER_BLOCK = """
   terraform {
     required_providers {
       aws = {
         source  = "hashicorp/aws"
         version = ">= 5.0, < 6.0"
       }
     }
   }
   """
   ```

2. **Add validation to the remediation pipeline:**
   ```bash
   # In CI, always validate before applying
   identity-guard remediate --policy-file $POLICY --output /tmp/fix.tf
   cd /tmp && terraform init -backend=false && terraform validate
   ```

3. **Add regression test:**
   ```python
   def test_remediation_produces_valid_terraform():
       policy = { ... }
       findings = scan_policy(policy)
       for finding in findings:
           tf_output = generate_remediation(finding, format="terraform")
           # Validate HCL syntax at minimum
           assert "resource" in tf_output or "data" in tf_output
           assert tf_output.count("{") == tf_output.count("}")
   ```

### Prevention

- Always run `terraform validate` on generated output in CI.
- Pin the AWS provider version in all templates.
- Maintain a test matrix of Terraform versions (1.5, 1.6, 1.7+).
- Add a `--dry-run` flag that shows the remediation without writing files.
- Consider generating OpenTofu-compatible output as well.

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
