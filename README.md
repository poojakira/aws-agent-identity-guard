# AWS Agent Identity Guard

IAM Permission Engineering Studio is a local policy-review tool for cloud developers and security reviewers. Paste or upload an IAM identity policy and optional role trust policy, run the actual repository scanner, inspect exact statement evidence, then edit and compare results.

**Complete-contract release status: PARTIAL.** This candidate implements a real local workflow; it is not production approval. Current test results belong in generated evidence tied to the checked-out commit. Historical metrics elsewhere do not attest to this candidate.

## Start locally

Requires Python 3.10+ and a browser. The studio has no runtime dependency, AWS credential requirement or paid service.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m aws_agent_identity_guard.studio
```

Open **http://127.0.0.1:8762**. The server accepts only the exact IPv4 loopback origin. Stop with Ctrl+C. Do not expose it with a tunnel or reverse proxy.

1. Load the labeled synthetic example, or paste/upload your own bounded identity JSON.
2. Add optional trust JSON. Click **Review IAM change** and select a finding to inspect its exact source statement, line, rationale, remediation and context.
3. Edit the policy and review again. Added/removed pattern findings link to After/Before source evidence.
4. Inspect the supplied-only relationship graph. Export SARIF 2.1.0, a text review, or complete evidence JSON. Exports contain supplied policy context; review before sharing.

![Actually running IAM studio with candidate evidence](https://raw.githubusercontent.com/poojakira/aws-agent-identity-guard/refs/tags/evidence/local-workbench-20261116/release-evidence/browser/desktop.png)

The image belongs to separately generated exact-source evidence, avoiding a source commit claiming to contain its own post-execution hash.

## What is supported

- **24 static rules:** AIG001–AIG021 and AIG-TP001–003, checked against the actual engine inventory. The product has an additional live-context rule, AIG-PB001, which checks missing boundary presence and does not run from static policy alone.
- Real canonical identity/trust scanners, exact structural source spans, source/configuration/input hashes and honest CLEAN/DIRTY/UNKNOWN provenance.
- Bounded JSON input, explicit unsupported-structure errors, edit/rescan comparison, supplied-only graph, safe rendering and schema-tested SARIF exports.
- Existing CLI and optional live-account/remediation adapters retain their separate interfaces and prerequisites. The studio neither invokes them nor claims their external validation.

Findings are patterns, **not effective permissions or proven exploitability**. Explicit Deny and conditions are displayed; their intersections, SCPs, permissions boundaries, session/resource policies and service-specific applicability are not evaluated. Effective permissions remain UNKNOWN. A zero finding count does not prove safety. AIG-PB001 presence checks do not prove boundary effectiveness. No live AWS validation or real-world accuracy rate is claimed.

Inputs stay in local process/browser memory; the backend does not persist them or use third-party APIs. Each document is limited to 32768 UTF-8 bytes, depth16 and32statements; action/resource/principal lists to64values. This is a single-user local tool, not authenticated multi-tenant hosting.

## Development and verification

The pinned test snapshot targets Linux x86_64/Python3.12. Runtime remains Python3.10+; platform/version tests must identify their actual environment.

```sh
python -m pip install -r requirements-studio-test.txt
python -m pip install -e .
curl -fLS https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json -o /tmp/iam-sarif-schema.json
echo 'c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e  /tmp/iam-sarif-schema.json' | sha256sum -c -
python scripts/studio_verify.py --output /tmp/iam-studio-evidence --schema /tmp/iam-sarif-schema.json --chromium /usr/bin/chromium
```

The browser gate needs Chromium at the chosen path; CI installs the tested Playwright browser. The verifier requires a clean source and generates commands/times, JUnit, coverage, scan exports, screenshots, builds, audit results and hashes outside the checkout. It preserves the existing minimum test-collection and performance gates. Three legacy rule-contract tests skip because their optional rules module is absent; no live AWS validation is claimed. The official schema is downloaded only for verification, never by the running studio. No schema source is vendored or relicensed.

For focused development: `SARIF_SCHEMA_PATH=/tmp/iam-sarif-schema.json python -m pytest tests/test_studio.py`. Without that prerequisite, the schema test is explicitly skipped. The existing static CLI remains `aws-agent-identity-guard POLICY.json --format sarif`.

## Documentation

- [Product, architecture, threat model, API, user/developer guides and operations](docs/STUDIO.md)
- [Evidence, release boundary and remaining gates](docs/EVIDENCE.md)
- [Read-only baseline audit](docs/internal/REPOSITORY_AUDIT.md)
- [Static versus live rule-inventory correction](docs/internal/RULE_INVENTORY_CORRECTION.md)
- [Security reporting](SECURITY.md)
- [Changelog](CHANGELOG.md)

Legacy CLI/live documents and dated evidence retain their context. Full historical fact/example/diagram reconciliation and safe branch consolidation remain incomplete; all unique/ambiguous branches are held. No release tag, public service, default-branch rewrite or branch deletion is performed by this candidate.
