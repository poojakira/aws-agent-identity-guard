# AWS and local security controls

The table maps checked-in behavior/configuration, not deployment approval. No target AWS account was configured or validated in this documentation pass.

| Control | Actual location/status | Residual boundary |
|---|---|---|
| Local keyless policy review | `studio/` and `scanner.py`; actual browser invokes canonical static rules | Single trusted operator/host; no public multi-user authentication |
| Bounded studio request/structural parsing | `studio.__main__`, `studio.analysis`, `tests/test_studio.py` | Not complete AWS language or general process isolation; CLI has a distinct contract |
| Actual source evidence and safe rendering | Structural spans, input/config/rule hashes, revision guards, text rendering, browser regression | Unsigned hashes and local host trust; external effects/effective permissions unknown |
| Optional read-only account collection | `live_scanner.py`; IAM/STS SDK read calls and completeness/errors | Operator must approve credentials, permissions, account and quota use |
| Incomplete live scan gate | CLI `--enforce` plus `scan_complete`/errors | Without enforcement a partial report can exit 0; full policy intersections still absent |
| Terraform scanner role | `infra/terraform/modules/scanner-iam/main.tf`; account principal `AssumeRole` plus ExternalId | Configuration only, not applied proof or GitHub OIDC; review account-principal breadth |
| CloudWatch log group | Terraform resource declared | No ordinary-collector log shipping is wired or verified |
| OIDC credential federation | Deployment proposal, not supplied by that Terraform module | Requires approved provider/audience/subject trust; web identity does not accept ExternalId |
| Dependency/workflow controls | Audits, test dependency snapshot and pinned checked-in Actions | Pins/audits do not prove vulnerability absence, publisher trust or reproducible images |
| Report privacy/integrity | Operator-owned artifact storage and byte/hash correspondence | Policies/ARNs may be sensitive; no automatic anonymization, encryption/backup or signature guarantee |

Security Hub/ASFF publication, GuardDuty/Config integration, KMS-backed artifact storage, VPC hosting, production recovery and deployment-specific legal/privacy/security approval are not established by these files. Whether they are necessary depends on the separately chosen environment. Do not describe a service as CLI-only when the local loopback studio also exists, or call a report non-sensitive merely because it omits secret keys.

See [AWS architecture](aws-architecture.md), [security policy](../SECURITY.md), [the studio contract](STUDIO.md) and [evidence](EVIDENCE.md). Earlier formatting/validation claims without an exact preserved run remain historical; current Terraform plan/apply is NOT VERIFIED and was not executed.
