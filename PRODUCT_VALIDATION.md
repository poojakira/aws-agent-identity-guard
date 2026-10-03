# Product Validation

## Product boundary
Pre-deployment static analysis for AWS IAM policies used by AI agents and tool-executing workloads. It is not an IAM entitlement graph, account-wide posture platform, or runtime authorization service.

## Real-world validation ladder
1. **Offline policy corpus** — deterministic tests over agent-role policies that exercise wildcard grants, PassRole, AssumeRole, trust-policy scoping, audit tampering, control-plane mutation, and permission-boundary expectations.
2. **AWS differential pilot** — when a dedicated read-only AWS validation role is configured, compare this tool's findings with AWS IAM Access Analyzer policy validation on the same policy documents.
3. **CI contract** — findings, exit codes, JSON/SARIF structure, and rule IDs are regression-gated.
4. **External pilot** — a real organization supplies redacted IAM policies and independently reviews false positives/false negatives.

## Evidence rules
- AWS service output is recorded only when the live pilot actually runs.
- Agreement with Access Analyzer does not prove effective permissions; this scanner still does not resolve SCPs, session policies, identity/resource policy interactions, or live resource state.
- No customer/adoption claim is allowed without an external participant and dated evidence.
