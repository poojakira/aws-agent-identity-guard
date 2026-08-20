# AWS Architecture  -  AWS Agent Identity Guard

## Purpose

This document is a reference design for running `aws-agent-identity-guard` as an
automated security check in an AWS-integrated CI/CD pipeline. The default product
surface is still a local static linter. Live scanning requires explicit AWS
configuration by the operator.

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
| **CloudWatch Logs** | Evidence retention | Provisioned by Terraform module; log shipping from the CLI is not implemented |

Services **not used** (and why):
- **S3**  -  Not needed for a CLI tool; scan artifacts are stored in CI artifact storage.
- **DynamoDB**  -  No persistent finding database at this scale.
- **Security Hub**  -  Future work: ASFF output format is prepared in code but publication not yet automated.

---

## IAM Roles

### `aws-agent-identity-guard-{env}-scanner-role`

- **Purpose:** Read-only IAM enumeration
- **Trust:** GitHub Actions OIDC endpoint (`token.actions.githubusercontent.com`) scoped to the deploying repository and branch
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
      "token.actions.githubusercontent.com:sub": "repo:OWNER/REPO:ref:refs/heads/main"
    }
  }
}
```

---

## Cost

No measured cost artifact is committed in this repository. Operators should
estimate AWS charges from their actual scan frequency, IAM role count,
CloudWatch retention settings, and current AWS pricing before enabling live
scan evidence retention.

---

## Security Controls

See [docs/aws-security-controls.md](aws-security-controls.md) for the full control mapping.

Key controls:
- No permanent AWS credentials are required by the reference design.
- Scanner role has `sts:ExternalId` condition in the Terraform module.
- GitHub Actions OIDC scoping must be set to the operator's repository and branch.
- Scanner permissions are intended to be read-only IAM enumeration.
- Terraform state encryption and locking are operator responsibilities outside this module.
