# AWS Architecture — AWS Agent Identity Guard

## Purpose

This document describes how `aws-agent-identity-guard` can be deployed as an automated security
gate in an AWS-integrated CI/CD pipeline, and how the live scanning mode authenticates to AWS
without long-lived credentials.

---

## Deployment Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                       GitHub Actions (CI/CD)                        │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  Push / PR event                                            │    │
│  │  → Lint job (ruff)                                         │    │
│  │  → Security job (bandit, pip-audit)                        │    │
│  │  → Test job (pytest)                                       │    │
│  │  → [Optional] Live scan job                                │    │
│  │       │                                                    │    │
│  │       └──── OIDC token ──────────────────────────────┐    │    │
│  └────────────────────────────────────────────────────── │ ───┘    │
└────────────────────────────────────────────────────────── │ ────────┘
                                                           │
                    ┌──────────────────────────────────────▼──────────┐
                    │           AWS STS (OIDC federation)              │
                    │  AssumeRoleWithWebIdentity                       │
                    │  Trust policy: github.com/poojakira/aws-agent... │
                    │  + sts:ExternalId condition                      │
                    └──────────────────────────────────────────────────┘
                                           │
                    ┌──────────────────────▼──────────────────────────┐
                    │       aws-agent-identity-guard-dev-scanner-role  │
                    │                                                  │
                    │  Policy: scanner-policy (read-only)              │
                    │  iam:ListRoles, iam:GetRole, iam:GetPolicy, ...  │
                    │  sts:GetCallerIdentity                           │
                    └──────────────────────────────────────────────────┘
                                           │
              ┌────────────────────────────┼───────────────────────────┐
              ▼                            ▼                           ▼
     ┌─────────────────┐        ┌──────────────────┐       ┌──────────────────┐
     │ IAM ListRoles / │        │ IAM GetPolicy /  │       │ CloudWatch Logs  │
     │ ListUsers       │        │ GetPolicyVersion │       │ (scan evidence)  │
     └─────────────────┘        └──────────────────┘       └──────────────────┘
```

---

## AWS Services Used

| Service | Justification | Usage |
|---------|--------------|-------|
| **AWS IAM** | Core subject of the scanner | Read-only enumeration of roles, users, policies |
| **AWS STS** | Temporary credential issuance | OIDC federation from GitHub Actions; `GetCallerIdentity` to resolve account ID |
| **CloudWatch Logs** | Evidence retention | Scan event logging in live mode |

Services **not used** (and why):
- **S3** — Not needed for a CLI tool; scan artifacts are stored in CI artifact storage.
- **DynamoDB** — No persistent finding database at this scale.
- **Security Hub** — Future work: ASFF output format is prepared in code but publication not yet automated.

---

## IAM Roles

### `aws-agent-identity-guard-{env}-scanner-role`

- **Purpose:** Read-only IAM enumeration
- **Trust:** GitHub Actions OIDC endpoint (`token.actions.githubusercontent.com`) scoped to this repository and `agent/security-hardening-v1` branch
- **Permissions:** `iam:ListRoles`, `iam:ListUsers`, `iam:GetRole`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListAttachedRolePolicies`, `iam:GetRolePolicy`, `iam:ListUserPolicies`, `iam:ListAttachedUserPolicies`, `iam:ListUserTags`, `sts:GetCallerIdentity`
- **No write permissions** to IAM or any other service
- **Confused-deputy protection:** `sts:ExternalId` condition required

---

## GitHub Actions OIDC Setup

```yaml
# In the live-scan CI job:
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: ${{ vars.AWS_SCANNER_ROLE_ARN }}
    role-external-id: ${{ secrets.AWS_SCANNER_EXTERNAL_ID }}
    aws-region: us-east-1
```

Trust policy for the role (example):
```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:poojakira/aws-agent-identity-guard:ref:refs/heads/agent/security-hardening-v1"
    }
  }
}
```

---

## Cost Estimate

For a CI pipeline running 20 scans/day against an account with ~100 IAM roles:

| Service | Usage | Estimated Cost |
|---------|-------|---------------|
| IAM API calls | ~300 read calls/scan × 20 = 6,000/day | Free (IAM API has no per-call cost) |
| STS AssumeRole | 20/day | Free |
| CloudWatch Logs | ~10 KB/scan × 20 = 200 KB/day | < $0.01/month |
| **Total** | | **< $0.10/month** |

---

## Security Controls

See [docs/aws-security-controls.md](aws-security-controls.md) for the full control mapping.

Key controls:
- No permanent AWS credentials stored anywhere
- Scanner role has `sts:ExternalId` condition (confused-deputy prevention)
- GitHub Actions OIDC scoped to this repository and branch
- All IAM permissions are read-only with no resource wildcards that could be abused
- Terraform state encrypted in S3 (when deployed) with DynamoDB locking
