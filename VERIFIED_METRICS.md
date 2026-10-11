# Verified Metrics

## Latest directly checked hosted CI - 2026-10-10

**Main commit:** [`bc35752dbfd72a7ce80eb1ad992bc6bc656d70fe`](https://github.com/poojakira/aws-agent-identity-guard/commit/bc35752dbfd72a7ce80eb1ad992bc6bc656d70fe)

**Successful CI:** [GitHub Actions run 38009457205](https://github.com/poojakira/aws-agent-identity-guard/actions/runs/38009457205)

- Python 3.12 JUnit-derived summary: **247 collected, 244 passed, 3 skipped, 0 failures, 0 errors**.
- Python 3.10, 3.11 and 3.12 tests, lint/format, security audit and synthetic performance gate completed successfully in the cited run.
- Skips require live AWS credentials; this is a static analyzer and no live AWS effective-permission evaluation is implied.
- Historical poster and September benchmark figures below remain valid only for their anchored snapshot; the October CI summary does not assert a new benchmark value.

## Historical main verification - 2026-09-30

**Code commit:** `c39ba67f43ef6ebddd03a8ce429b42afec0c08a9`  
**Successful CI:** https://github.com/poojakira/aws-agent-identity-guard/actions/runs/36781556871

| Claim | Historical verified value | Scope |
|---|---:|---|
| Test result | **243 collected, 240 passed, 3 skipped** | September 2026 CI at cited commit |
| Deterministic rule IDs | **25** | Static rule inventory at cited commit |
| Performance p95 | **0.8397 ms/policy** | September 2026 CI, 500 synthetic policies |
| Performance throughput | **2,573 policies/sec** | Same synthetic gate |
| Configured p95 gate | **< 10 ms/policy** | Gate threshold, not an SLO |
| Configured throughput gate | **> 1,000 policies/sec** | Gate threshold, not an SLO |

The 3 skipped tests require AWS credentials. Do not commit credentials; use `AWS_PROFILE`, SSO/STS, or workload-role credentials through the standard provider chain.

## Claim boundary

This repository performs static IAM analysis. It does not establish runtime enforcement, production reliability, or complete account-wide effective permissions.
