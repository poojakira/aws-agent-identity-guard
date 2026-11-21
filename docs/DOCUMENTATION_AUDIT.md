# Documentation reconciliation audit

## Scope and decision

All **32** original tracked `.md`, `.mdx`, `.rst` and `.txt` documents at implementation source `970d1e1e3d5e65e91bd45fe16bb59725eec7b1dc` were read completely. Root LICENSE was additionally read; legal/raw license and dependency snapshot files remain unchanged. Actual CLI/scanner/studio/live/remediation code, Terraform, n8n template, tests and workflows were consulted. Rule-based template selection does not make timestamped remediation output byte-identical. This page is the new audit ledger.

**Documentation reconciliation is complete within this recorded local scope; release remains PARTIAL.** Reading/source cross-checking is distinct from executing commands, live AWS validation, external historical fact verification or production approval. Later-head full regression/browser/security/build checks remain pending until a generated exact-source manifest exists. See [EVIDENCE.md](EVIDENCE.md).

## Corrections and source relationships

- README/user/API guidance describes actual loopback parsing, canonical scanning, source-linked comparison, supplied-only graph, exports and data lifecycle.
- Rule inventory is 24 static checks plus the separate live-context AIG-PB001; static findings do not establish effective permissions or exploitability.
- CLI `--format`, exit status, exact-role filter, JSON/report shape, `--enforce`, completeness and rule-based remediation contracts match `cli.py`, `live_scanner.py` and `remediate.py`.
- Removed invented response deadlines, gate-bypass instructions, fake live output, deployment-safe exit-0 language and assumed CI integrations. Preserved useful optional read permissions/workflow guidance with explicit authorization and unmet prerequisites.
- Terraform account-principal AssumeRole/ExternalId is separated from proposed OIDC. No ordinary collector CloudWatch/CloudTrail delivery, configured remote backend, measured costs or resource-wildcard-free privilege claim is invented.
- Delegated-credentials tests are mocked local guard/expiration/dictionary checks, not actual STS web-identity authorization. The generated helper trust dictionary must not be deployed unchanged: WebIdentity has no ExternalId request parameter. Runtime code, rules and tests were preserved.
- Historical metrics/posters are source-dated, with legacy rules-module skip reasons verified in the cited October source. Current evidence, completed independent implementation-source review and two safe merged-branch deletions are distinguished from later-head verification.

| Contract | Source/test relationships consulted |
|---|---|
| Static identity/trust patterns and inventory | `scanner.py`, studio analysis inventory, scanner/trust/condition/killchain tests |
| HTTP/input/source/graph/export | `studio/__main__.py`, `analysis.py`, `studio.js`, `tests/test_studio.py`, actual browser/schema scripts |
| CLI/error/SARIF/remediation | `cli.py`, `remediate.py`, CLI/failure/remediation tests |
| Optional collection/completeness | `live_scanner.py`, mocked live/enforcement tests |
| AWS configuration/delegated mock | Terraform module/dev source, example Python and six mocked tests |
| Optional automation | n8n JSON nodes, CLI exit/completeness semantics; no import/activation performed |
| Fresh evidence and release/build | `scripts/studio_verify.py`, checked-in workflows, package metadata, historical manifests |

## Per-document disposition

| Document | Disposition | Review boundary |
|---|---|---|
| `CHANGELOG.md` | Unreleased documentation changes | Records presentation and evidence corrections; runtime, rules and gates are unchanged. |
| `CONTRIBUTING.md` | Authorized development; legal preamble preserved | Actual source/test entry points, rule scope and evidence requirements; no rights change. |
| `INCIDENT_RUNBOOK.md` | Consolidated response template | Removed gate bypass, release commands, invented deadlines and incorrect remediation claims. |
| `PRODUCTION.md` | Current release gates | PARTIAL status, full candidate checks and deployment/privacy/recovery limits. |
| `PRODUCT_VALIDATION.md` | Historical context preserved | Conditional validation ladder; no external pilot or adoption result revalidated. |
| `PROVENANCE.md` | Historical context preserved | Maintainer chronology remains distinct from Git; external artifacts not independently retrieved. |
| `README.md` | Current onboarding and index | Real local review, 24 static rules plus one live-context ID, prior proof and later-head pending status. |
| `RESUME_EVIDENCE.md` | Compatibility pointer preserved | Older submitted metrics remain tied to their cited sources. |
| `RUNBOOK.md` | Consolidated interface contracts | Correct static count, exit statuses, exact-role filtering, completeness and remediation behavior. |
| `SECURITY.md` | Current security/reporting guidance | No invented SLA or absolute safety claims; credential/report privacy and residual risk. |
| `SECURITY_AUDIT.md` | Historical report retained | Dated findings are not a current no-web-surface or independent candidate assessment. |
| `SECURITY_AUDIT_2026-09-30.md` | Historical report retained | Old workflow checkpoint remains source-specific; the later studio has a different surface. |
| `THREAT_MODEL.md` | Current controls and risk mapping | Studio/CLI/live boundaries, incomplete IAM semantics, artifact privacy and mocked OIDC limitation. |
| `VERIFIED_METRICS.md` | Source-scoped snapshots reconciled | 970d run 267/3; older 244/3 remains dated; skip reason checked in cited source. |
| `docs/EVIDENCE.md` | Current evidence/governance reference | Prior archive/review/CI scope, two deleted branch recovery tags and later-head pending proof. |
| `docs/OPERATIONAL_IAM_REMEDIATION_MEASUREMENT.md` | Unexecuted authorized method clarified | Static finding reduction does not establish effective-permission or live-role reduction. |
| `docs/PERFORMANCE_BASELINE.md` | Threshold versus result clarified | Existing 500-policy synthetic gate retained; no field performance or SLO claim. |
| `docs/RECRUITER_EVIDENCE_AUDIT_2026-10-09.md` | Historical inventory/context corrected | 25 product IDs have separate static/live scope; cross-product figures remain dated. |
| `docs/STUDIO.md` | Actual contract retained and status updated | Completed implementation review/cleanup is separate from later-head verification. |
| `docs/aws-architecture.md` | Actual configuration/trust distinction | Account AssumeRole differs from OIDC; no invented log delivery, backend or cost proof. |
| `docs/aws-security-controls.md` | Checked-in control mapping | Source/configuration versus planned deployment; sensitive reports and offline/live distinctions. |
| `docs/evidence/RESUME_EVIDENCE.md` | Historical submitted record preserved | 230-test application anchor and synthetic performance are not current-head evidence. |
| `docs/internal/REPOSITORY_AUDIT.md` | Original read-only baseline preserved | Pre-studio main, dashboard and branch observations remain explicitly historical. |
| `docs/internal/RULE_INVENTORY_CORRECTION.md` | Reviewed; accurate correction preserved | 24 canonical static IDs plus live AIG-PB001 match code/tests; no AWS call used. |
| `docs/license-history/LICENSE-BEFORE-2026-10-13.txt` | Read; legal text preserved unchanged | Historical grants and attribution were not modified. |
| `examples/delegated_credentials/README.md` | Mock/API limitation corrected | Local guard/moto does not prove AWS WebIdentity authorization; runtime/tests unchanged. |
| `integrations/N8N_WORKFLOW.md` | Template behavior/gaps documented | Exit routing, incomplete scans, duplicate tickets and external sharing require review. |
| `poster/01_research_brief.md` | Historical source/scope corrected | 718 snapshot, 24 static plus one live-context check and legacy-module skip reason. |
| `poster/02_claim_ledger.md` | Historical source/scope corrected | Claims attest to cited source; benchmark remains separate. |
| `poster/03_verified_metrics.md` | Historical source/scope corrected | 247/244/3 stays dated; corrected skip and product inventory labels. |
| `poster/13_reproducibility.md` | Historical source/scope corrected | Pinned 718 checkout; no current-head pass or credential-dependent skip fiction. |
| `requirements-studio-test.txt` | Read; verification snapshot preserved unchanged | Tool dependencies are not runtime requirements or wheel-hash locks. |

## Execution and verification boundaries

Executed during this pass: supported CLI/studio help, documentation JSON/shell syntax checks, an actual documented studio request through a fresh loopback server/canonical scanner, static CLI text/JSON/SARIF examples and the separate six-case moto delegated-credentials suite. Syntax parsing is not execution of every shell/cloud command. Exact commands, exits, UTC intervals, source observations and raw logs are retained out of the source checkout. No live AWS query, Terraform apply, n8n activation, Slack/Jira/email message, provider key or paid service was used.

The actual poster renderer generated a real 36×48-inch single-page PDF and 1800×2400 PNG using the host's real PyMuPDF and an external Chromium/Playwright-backed PDF build wrapper. The wrapper supplies only the exact project-generated trusted HTML through normal `set_content`; it changes no HOME, browser policy, runtime logic, authentication or security gate. Visual/PDF-text review checks the historical date/source, 24-static-plus-one-live inventory, absent-legacy-module skips and populated evidence panel. Repeated PNG hashes establish local content repeatability; volatile PDF metadata can differ, and local browser/fonts do not establish hosted parity. The renderer changes only presentation labels/diagram text, not product behavior.

Independent implementation-source review, published artifacts and branch recovery are described in [EVIDENCE.md](EVIDENCE.md). That prior proof does not attest to this documentation head. External URL reachability is a separate bounded check, not linked claim truth or remote-anchor validation. External chronology/benchmark/adoption assertions remain unverified unless their original artifacts are independently inspected. Registry distribution identity, Terraform plan/apply, cloud credential trust, all effective-policy intersections, real field accuracy, external delivery and operational/privacy recovery remain separate release gates.

The current guides replace competing unsupported instructions while older raw legal/history evidence is preserved with explicit context. No unique branch, default history or historical commit timestamp was changed. Generated poster bot commits must be inspected before treating a hosted source head as frozen.
