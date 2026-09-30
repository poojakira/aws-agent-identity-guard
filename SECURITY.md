# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch | ✅ Active |
| Older tags | ❌ No patch support |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: `security@poojakiran.dev` (or open a private GitHub Security Advisory).

Include:
- A description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

You will receive a response within **72 hours**. If confirmed, a fix will be developed within **14 days** for critical/high severity.

## Scope

This tool is a **static IAM policy linter**. Its attack surface is:

1. **CLI input parsing** — `argparse` on local file paths. Path traversal is not possible since the tool only reads the specified file.
2. **JSON parsing** — `json.loads` on policy document content. No arbitrary code execution path exists.
3. **Live scanning mode** — Uses Boto3 with the standard AWS credential chain. The tool only calls read-only IAM APIs. It does not modify any AWS resources.
4. **SARIF output** — Writes structured JSON to a file. Output is not executed.

## Out of Scope

- Denial of service against the local CLI process
- AWS account compromise through the scanner identity (mitigated by read-only IAM policy)
- Vulnerabilities in third-party dependencies (report upstream; we track via `pip-audit`)

## Security Controls

- No runtime dependencies (static analysis only)
- Live scanning requires explicit `[live]` install and AWS credentials
- CI runs `bandit`, `pip-audit`, and `ruff` on every pull request
- GitHub Actions pinned to commit SHAs
- Workflow permissions: `contents: read` minimum

<!-- credential-response:start -->
## Credential and secret handling

- Real API keys, tokens, passwords, private keys, cloud credentials, and populated environment files must never be committed.
- Local users must create their own `.env` from the repository's safe template when environment variables are needed, and must supply **their own** credentials. CI/CD credentials belong in GitHub repository/environment secrets or an external secret manager, not in source or workflow YAML.
- If a real credential is exposed, treat it as compromised even if the commit is quickly deleted. **Revoke or rotate the credential at its provider first.** Then remove it from the current tree, reachable Git history, logs/artifacts, examples, screenshots, and documentation as applicable.
- Rewriting Git history or deleting a file does **not** revoke a credential. Provider-side rotation/revocation is required.
- Placeholder/test credentials must be clearly marked and must not be valid for real services.
<!-- credential-response:end -->
