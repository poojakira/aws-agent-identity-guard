# Design Decisions

Why this tool is shaped the way it is. Written for anyone reviewing the design from an IAM security or agent security perspective.

## Why static analysis and not runtime enforcement?

I considered three approaches:

1. **Runtime IAM boundary enforcement** (like AWS Permission Boundaries or SCPs) — these work but require org-level access. A security engineer evaluating an agent role before deployment often doesn't have org admin. Static analysis runs on the policy JSON alone.
2. **IAM Access Analyzer** — AWS's built-in tool. It checks for externally-accessible resources, not for agent-specific threats. It won't flag `iam:PassRole` without conditions because that's technically valid IAM — it just happens to be a privilege escalation path when the principal is an autonomous agent.
3. **Static lint (this tool)** — runs locally, no AWS credentials, catches agent-specific patterns that AWS's own tools don't flag.

The key insight: **what's dangerous for an agent role is different from what's dangerous for a human role.** A human with `sts:AssumeRole` on `*` is bad but recoverable — you revoke their session. An agent with the same permission can chain it programmatically, assume 50 roles in 200ms, and exfiltrate data from all of them before anyone notices. The rules in this tool encode that difference.

## Why 25 rules and not 100?

I started with 8 rules covering the obvious cases (wildcards, PassRole, CloudTrail). Then I studied IAM policies from 30+ public Bedrock/SageMaker agent examples on GitHub and AWS documentation. Each time I found a pattern that would let an agent escalate, pivot, or cover its tracks, I wrote a rule.

I stopped at 25 because I ran out of distinct patterns. The remaining candidates were either:
- Duplicates of existing rules with different action names (covered by the wildcard detection)
- Context-dependent checks that need runtime information (what other roles exist in the account) — those belong in live mode, not static analysis

I'd rather have 25 rules that all fire on real threats than 100 rules where 75 are noisy. Every rule in this tool traces back to a concrete attack path documented in `THREAT_MODEL.md`.

## Why zero dependencies?

Three reasons:

1. **Installs in any CI environment.** No native extensions, no Docker, no pip install failures on obscure build systems. `pip install aws-agent-identity-guard` works on every runner I've tested (GitHub Actions, GitLab CI, CircleCI, Jenkins, local macOS/Linux/Windows).
2. **No supply-chain attack surface.** A security tool with 30 transitive dependencies is itself a supply-chain risk. This tool depends on nothing beyond Python stdlib.
3. **Auditability.** The entire codebase is reviewable by one person in an afternoon. No hidden behavior in third-party packages.

The tradeoff: I reimplemented a simple SARIF emitter (50 lines) instead of using a library. I reimplemented JSON path extraction instead of using jmespath. These are small trade-offs for the guarantee of zero dependencies.

## Why SARIF and not just JSON?

SARIF gives you GitHub Code Scanning integration for free. Upload a SARIF file and developers see inline annotations on the policy file in their PR diff. That's the difference between "the security scanner found something, go read the log" and "there's a red annotation on line 12 of your policy file saying what's wrong."

I also output plain text (for terminal use) and JSON (for scripting). But SARIF is the primary format because it has the best developer experience when paired with GitHub.

## Why two modes (Local / Live)?

Local mode exists because most CI pipelines don't have AWS credentials available — they're scanning policy files that are committed to the repo, not deployed yet. Local mode reads `policy.json` from disk and applies rules to it.

Live mode exists because some teams want to scan policies that are already deployed. It uses `boto3` to call `iam:GetRolePolicy` and `iam:ListAttachedRolePolicies`, then applies the same 25 rules. This is useful for drift detection — "did someone manually attach a wildcard policy after the CI gate approved the original?"

Live mode is optional. It's the only thing that requires `boto3`, and `boto3` is an optional dependency (`pip install aws-agent-identity-guard[live]`).

## Why exit code 1 instead of just reporting?

Security tools that only report are ignored. I've seen organizations with beautiful SAST dashboards showing 400 open critical findings — none of which ever get fixed because they don't block anything.

Exit code 1 on critical/high means the PR can't merge until the policy is fixed. This is opinionated and I'm comfortable with it. The `--fail-on` flag lets teams lower the threshold (fail on medium) or raise it (fail only on critical) depending on their risk tolerance.

The default is aggressive because agent roles are high-risk principals. An over-permissioned agent role is not equivalent to an over-permissioned Lambda function — the agent acts autonomously and can chain operations in ways that a static function cannot.

## What I'd build next

- **Policy suggestion mode** — instead of just flagging `s3:*`, output a least-privilege policy with the specific actions the agent actually needs (based on CloudTrail analysis of what it's called in the past)
- **Temporal analysis** — compare the policy at this commit to the policy at the last commit. Flag permissions that were added, not just permissions that exist.
- **Organization-level rules** — some rules only make sense in the context of other policies in the account. "This role can assume Role B, and Role B has admin access" is a transitive escalation that requires multi-role analysis.
- **CloudTrail correlation** — feed SARIF findings into Splunk or Sentinel alongside CloudTrail logs. A SIEM correlation rule can then detect "agent role was flagged as over-permissioned at deploy time AND the agent is now actively exercising the flagged permission." I have prototype Sigma rules for this (`sigma/agent_privesc_exercised.yml`) that fire when CloudTrail shows an sts:AssumeRole matching a CRED-002 finding from the static scan. The gap between "this policy could be abused" and "this policy is being abused right now" is what detection engineering closes.
- **SOAR auto-remediation** — on critical findings in live mode, emit a webhook that triggers a Cortex XSOAR playbook to attach a deny-all permission boundary to the role immediately, then page the role owner. Faster than waiting for someone to read the SARIF report.

## Threat model summary

The documented threat model (`THREAT_MODEL.md`) assumes:
- The agent role is a first-class autonomous principal
- The attacker either compromises the agent (via prompt injection) or deploys a malicious agent role directly
- Attack goals: data exfiltration, privilege escalation, lateral movement to other ML services, audit evasion
- The CI gate is the last defense before a dangerous policy reaches production
