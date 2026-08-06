# AWS Security Controls — AWS Agent Identity Guard

## Control Matrix

| Control | Implementation | Status |
|---------|---------------|--------|
| No permanent AWS credentials | GitHub Actions OIDC federation (STS AssumeRoleWithWebIdentity) | PLANNED — requires OIDC provider setup in target account |
| Least-privilege scanner role | Read-only IAM policy (see `infra/terraform/modules/scanner-iam/main.tf`) | IMPLEMENTED (Terraform) |
| Confused-deputy prevention | `sts:ExternalId` condition on trust policy | IMPLEMENTED (Terraform) |
| Source restriction | GitHub Actions OIDC scoped to repository + branch | PLANNED |
| No public endpoints | Tool is CLI-only; no API server | N/A |
| Dependency integrity | `pip-audit` in CI | IMPLEMENTED |
| Supply-chain integrity | GitHub Actions SHA-pinned | IMPLEMENTED |
| Scan evidence | CloudWatch Logs group provisioned | PLANNED — log shipping not yet wired |

## What Is Not Implemented

| Control | Reason | Risk |
|---------|--------|------|
| Security Hub ASFF publishing | Requires Security Hub enabled in account and additional IAM permissions | Low — SARIF upload to GitHub covers CI use case |
| GuardDuty integration | Not applicable to a read-only scanner | N/A |
| KMS encryption of scan artifacts | Scan output contains no sensitive data beyond role names/ARNs | Accepted |
| VPC deployment | No network-accessible endpoints exist | N/A |

## Compliance Notes

This tool is a developer/security-team utility. It is not a production service.
Security Hub, Config, and GuardDuty are not required for operation.

The Terraform in `infra/` has been formatted with `terraform fmt` and validated with `terraform validate`.
It has **not** been applied against a real AWS account as of this PR.
Run `terraform plan` before applying to verify the resources it would create.
