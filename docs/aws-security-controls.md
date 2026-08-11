# AWS Security Controls — AWS Agent Identity Guard

## Control Matrix

| Control | Implementation | Status |
|---------|---------------|--------|
| No permanent AWS credentials | GitHub Actions OIDC federation (STS AssumeRoleWithWebIdentity) | PLANNED — requires OIDC provider setup in target account |
| Least-privilege scanner role | Read-only IAM policy template (see `infra/terraform/modules/scanner-iam/main.tf`) | IMPLEMENTED AS IaC TEMPLATE |
| Confused-deputy prevention | `sts:ExternalId` condition on trust policy | IMPLEMENTED AS IaC TEMPLATE |
| Source restriction | GitHub Actions OIDC scoped to repository + branch | PLANNED |
| No public endpoints | Tool is CLI-only; no API server | N/A |
| Dependency integrity | `pip-audit` in CI | IMPLEMENTED IN WORKFLOW |
| Supply-chain integrity | GitHub Actions SHA-pinned | IMPLEMENTED IN WORKFLOW |
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

No committed artifact proves this Terraform has been applied to a real AWS
account. Run `terraform fmt`, `terraform validate`, and `terraform plan` in your
target account before applying, then retain those outputs as deployment evidence.
