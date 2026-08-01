# AWS Agent Identity Guard

Static IAM and trust-policy checks for agentic AI workloads on AWS.

The July/August 2026 security problem this targets is not another generic cloud misconfiguration scanner. AWS guidance for generative AI agents calls out excessive autonomy, session isolation, and IAM complexity as first-order risks for agents that can call tools, hold memory, and act across systems. CSA's 2026 cloud-threat survey also moved identity, AI, third-party dependencies, and APIs to the center of cloud risk. This project focuses on that intersection: agent identities with too much AWS authority.

## What It Checks

- Wildcard actions or resources in policies attached to agent runtimes
- `iam:PassRole` without `iam:PassedToService` constraints
- Privilege-management actions such as `iam:*`, `sts:AssumeRole`, and policy attachment APIs
- Broad Bedrock, Lambda, SSM, Secrets Manager, KMS, S3, and CloudWatch Logs permissions
- Trust policies missing external IDs, source-account/source-ARN constraints, or session-tag expectations
- Findings mapped to severity and a concrete remediation note

## Usage

```bash
python -m pip install -e .
aws-agent-identity-guard examples/agent_policy_wildcard.json --format text
aws-agent-identity-guard examples/agent_policy_wildcard.json --format json
```

Exit codes:

- `0`: no high or critical findings
- `1`: at least one high or critical finding
- `2`: invalid input or CLI usage

## Scope

This is a deterministic static analyzer for IAM JSON documents. It does not call AWS APIs, does not need credentials, and does not claim runtime enforcement. Use it in CI before deploying Bedrock agents, MCP servers, Lambda tools, Security Agent jobs, or other autonomous workloads that receive AWS permissions.

## Evidence

The current repository ships unit tests and example policies. Public benchmark, false-positive, or enterprise deployment claims require committed evaluation artifacts and should not be inferred from this README.
