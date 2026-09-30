# Verified Metrics

## Current main verification - 2026-09-30

**Code commit:** `c39ba67f43ef6ebddd03a8ce429b42afec0c08a9`  
**Successful CI:** https://github.com/poojakira/aws-agent-identity-guard/actions/runs/36781556871

| Claim | Current verified value | Scope |
|---|---:|---|
| Test result | **238 collected, 235 passed, 3 skipped** | Current-main CI |
| Deterministic rule IDs | **25** | Current scanner/live-scanner rule set |
| Performance p95 | **1.1460 ms/policy** | Current CI, 500 synthetic policies |
| Performance throughput | **1,846 policies/sec** | Same synthetic gate |
| Configured p95 gate | **< 10 ms/policy** | Gate threshold, not an SLO |
| Configured throughput gate | **> 1,000 policies/sec** | Gate threshold, not an SLO |

The 3 skipped tests require AWS credentials. Do not commit credentials; use `AWS_PROFILE`, SSO/STS, or workload-role credentials through the standard provider chain.

## Claim boundary

This repository performs static IAM analysis. It does not establish runtime enforcement, production reliability, or complete account-wide effective permissions.
