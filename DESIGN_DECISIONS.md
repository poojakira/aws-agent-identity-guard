# Design Decisions

## Why a Separate Authorization Service (Not Just IAM)

IAM answers "can this principal perform this action?" but cannot answer:
- "Should this AI agent perform this action given its declared purpose?"
- "Does this action create an attack path to sensitive resources?"
- "Is this action anomalous compared to the agent's normal behavior?"

Agent Identity Guard adds context-aware, intent-aligned authorization on top of IAM.

## Fail-Closed by Default in Production

If the authorization service is unavailable, production agents are denied by default. This is the security-conservative choice. Development environments can be configured fail-open.

## Multidimensional Risk Scoring

A single severity level (HIGH/MEDIUM/LOW) loses too much information. An action that is HIGH severity in production with sensitive data is different from HIGH severity in dev with test data. The 8-dimension risk score captures this nuance.

## Policy as Code, Not Configuration

Security policies are YAML files checked into Git, versioned, reviewed, and tested like application code. This gives security teams the same workflows as developers.

## Hash-Chain Audit Trail

Each audit event includes a hash of the previous event, creating a tamper-evident chain. If any event is modified or deleted, the chain breaks and integrity verification fails.

## No External Dependencies for Core Scanning

The static policy scanner has zero dependencies beyond Python stdlib. This means it can run in any CI environment without setup complexity. The runtime authorization server adds dependencies (PyYAML, optional Redis) but the core analysis is dependency-free.

## Agent Manifests as the Source of Truth

Developers declare what their agent is supposed to do in a manifest file. This creates a contract that the security system can verify. Without declared intent, the system can only flag suspicious patterns - with a manifest, it can identify violations of stated purpose.

## Performance Budget: <10ms for Authorization

Inline security controls must not materially impact agent latency. The 10ms budget allows for policy evaluation, risk scoring, and decision caching. Complex analysis (attack paths, drift detection) runs asynchronously.
