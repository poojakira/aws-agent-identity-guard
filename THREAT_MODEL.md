# Threat Model Summary

See [docs/threat-model.md](docs/threat-model.md) for the complete formal threat model.

## Trust Boundaries

1. Agent -> Guard API (untrusted)
2. Guard API -> Policy Store (trusted)
3. Guard API -> AWS APIs (semi-trusted)
4. Dashboard -> Guard API (authenticated)

## Key Threats

| Threat | Mitigation |
|--------|------------|
| Agent bypasses authorization | Fail-closed enforcement, SDK middleware |
| Policy tampering | Versioned policies, integrity checks |
| Audit trail manipulation | Hash-chain integrity, append-only |
| Privilege escalation via Guard | Minimal IAM role, no admin access |
| Denial of service | Rate limiting, circuit breaker |
| Credential exposure | No secrets in logs, env-var only |

## What We Do NOT Protect Against

- Compromised AWS control plane
- Physical access to infrastructure
- Supply-chain attacks on AWS SDKs
- Insider threat with admin access to Guard itself
- Network-level attacks below the application layer
