# Security Audit — 2026-09-30

## Scope
Initial pre-remediation review of current `main`.

## Runtime surface
Static IAM/policy analysis, integrations, Terraform examples, container build.

## Verified controls
- Analyzer is intended for static policy inspection.
- CI, Dependabot, security-hygiene workflow, container, release, incident, production, and AWS security documentation exist.
- No confirmed live AWS credential was found in the current main branch.

## Findings to remediate/verify
1. Terraform examples must use least-privilege policies and never embed credentials.
2. Ensure analyzer never calls privileged AWS mutation APIs by default.
3. Bound policy-document size/depth to resist parser/resource exhaustion.
4. Escape untrusted policy text in SARIF/HTML/Markdown outputs.
5. Verify integration examples store tokens only in secret stores/environment variables.

## Not applicable
Password reset, SQL tenant isolation, web rate limiting unless a network service is added.
