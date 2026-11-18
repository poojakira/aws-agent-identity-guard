# Security policy

## Scope and support

Software/studio version is 0.3.0. Main is the integration branch; no backport, acknowledgment deadline or fix-time commitment is published. Release status is **PARTIAL**. See [exact-source evidence](docs/EVIDENCE.md) before inferring support from a version or workflow name.

The local studio invokes actual static scanners without AWS credentials or third-party runtime dependencies. Its loopback/Host/Origin, parsing bounds, rate/socket limits and safe rendering are a local single-operator boundary, not authentication against another OS user or a multi-tenant service. CLI parsing has a different, less bounded contract. Optional Boto3 collection requires explicit credentials and IAM/STS access. Rule-based remediation prints suggestions; it does not apply changes.

## Vulnerability reporting

Report privately using the repository's GitHub security-advisory channel if available, or contact the maintainer through [the repository owner's profile](https://github.com/poojakira). Do not put credentials or exploitable details into a public issue. Include the affected commit/version, prerequisites, minimal synthetic reproduction, actual/expected behavior and impact. The project does not establish a staffed on-call service or a 72-hour/14-day SLA.

## Credentials and policy privacy

- Never commit real keys, passwords, session tokens, private keys, populated environment files or user policy inputs.
- Studio operation needs no AWS credentials. Use synthetic data for evaluation.
- Optional live work uses an operator-owned approved SDK credential provider. Prefer short-lived credentials; protect process memory, logs and artifacts.
- Revoke/rotate exposed credentials at their provider first, then preserve evidence and address source/history/artifact exposure under a reviewed recovery plan. Deleting a file or rewriting history does not revoke a credential.
- Policy reports may reveal account/resource relationships, identities and internal names. Restrict storage/sharing rather than calling ARNs or generated reports non-sensitive by default.
- No live credential checking or external validation is required to classify a secret-scan heuristic.

## Residual risk

Findings are heuristics, not effective-permission or exploitability proofs. Deny/SCP/boundary/session/resource intersections, service-specific condition semantics and complete live inventory remain unknown. A dependency audit, pinned Actions SHA or schema test reduces specific risk; none proves absence of supply-chain compromise or vulnerabilities. Large CLI inputs, local-process access, compromised hosts and maliciously replaced outputs remain concerns. Unkeyed hashes provide byte correspondence, not an independently signed attestation. Consult [the threat model](THREAT_MODEL.md), [operations](RUNBOOK.md), [release gates](PRODUCTION.md) and [studio contract](docs/STUDIO.md).
