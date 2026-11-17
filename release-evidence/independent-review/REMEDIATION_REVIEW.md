# Independent IAM remediation verification

PRODUCT: poojakira/aws-agent-identity-guard
SOURCE: 970d1e1e3d5e65e91bd45fe16bb59725eec7b1dc
BRANCH: codex/local-workbench-20261116
PHASE: Fresh independent recheck of capability wording and asynchronous uploads
DECISION: PARTIAL for the complete master acceptance contract. F1 and F2 from source68d109dfc59ced193c4efeeaed27c765640363de are CLOSED at this corrected source.

## Fresh executed results

- **38 independent checks passed, zero failed.** The actual engines, local HTTP and Chromium browser were used. `independent-checks.json` records exact source, UTC start/end and outcomes; the reproducible script is `independent_checks.py`.
- **Python3.10.22: 23 focused studio tests passed, zero failures/errors/skips**, with the pinned official SARIF schema supplied. Results: `python310-junit.xml`, `python310-tests.log`.
- All **42** artifact digests listed in the frozen final engineering manifest matched, and its source matched the clean checkout. This verifies artifact consistency; it is not an independent rerun of the entire engineering regression.
- The newly built wheel's checksum matched that exact-source manifest. It was installed without dependencies inside an unrelated synthetic Git repository. Actual HTTP startup, health and policy analysis passed, returned UNKNOWN source/status, and emitted the corrected canonical messages. `wheel-provenance.json`, `wheel-install.log`.
- All checked-in workflows again passed actionlint, recorded in `actionlint.log` and the independent check result.

Commands were run from the candidate checkout:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src SARIF_SCHEMA_PATH=/workspace/work/references/sarif-schema-2.1.0.json /workspace/work/reviews/aws-agent-identity-guard/venv310/bin/python -m pytest -p no:cacheprovider tests/test_studio.py -q --junitxml=/workspace/work/reviews/aws-agent-identity-guard/remediation-970d1e1/python310-junit.xml
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /workspace/work/envs/iam/bin/python /workspace/work/reviews/aws-agent-identity-guard/remediation-970d1e1/independent_checks.py
```

The wheel was reinstalled using `pip install --no-deps --force-reinstall` in the unrelated-project venv, then its real HTTP server was started and queried. The source checkout remained clean and unchanged throughout review. No remote refs, branches, tags, PRs, credentials or cloud resources were changed.

## Per-finding closure

| Prior finding | Corrected behavior | Independent reproduction | Disposition |
|---|---|---|---|
| F1: list-only policy findings assert arbitrary content/cross-service capabilities | Canonical AIG003 limits Resource:* interpretation to listed actions and explicitly rejects unlisted grants. AIG007 distinguishes sensitive-data/metadata actions and does not infer reading secret values or object contents from listing | The original ListBucket-only input now produces the same pattern IDs with qualified messages. This passed both direct canonical studio analysis and an actual newly installed-wheel HTTP request | CLOSED |
| F2: delayed file completion leaves an intervening old review enabled | Uploads guard their captured revision, discard obsolete reads and invalidate at actual editor assignment | Original delayed identity-file/read-and-review reproduction now clears exports. The same real-backend sequence passed for trust uploads. Newer manual identity and trust edits were each reviewed while an obsolete file read was pending; that old file did not overwrite the edit or invalidate its matching new evidence | CLOSED |

The additional asynchronous checks delayed only local File.text completion; every analysis still reached the real backend. After newer manual reviews, downloaded exports matched the newer editor text's SHA256. These are `manual-policy-review.json` and `manual-trust-review.json`. The current-candidate screenshot is `browser-race.png`; its filename identifies the regression scenario, not a remaining failure.

The original failures and original-source exports remain preserved in the parent review directory. They are historical proof and do not attest to this corrected commit.

## Other verified boundaries and remaining scope

The independent checks also passed for escaped structural JSON keys and exact spans, canonical finding identity, Deny/condition counter-context, duplicated escaped keys, malformed/non-finite/deep/oversized input and keys, official SARIF2.1.0 schema and source regions, supplied-only graph IDs, stable hashes, Host/Origin/body/extra-target rejection, safe HTML-shaped principal rendering, mobile bounds, current-source exports and absence of uncaught browser errors. Schema validity is not proof of security interpretation.

The separate exact-source engineering manifest records270 collected,267 passed and3 skipped, with77.14791851% statement coverage. Its three skips remain the absent optional rules-module tests, not successful tests or live AWS validation. Detection conditions/IDs were retained while the canonical descriptions were corrected.

The full contract remains PARTIAL. Effective-IAM evaluation, applicable Deny/SCP/boundary/session/resource-policy intersections, live role context and proven exploitability remain outside this local static flow. Complete legacy-document reconciliation, full build locks/installed source attribution, remote CI/protection visibility, complete branch consolidation, immutable archive public accessibility and environment-specific operational approval remain outstanding. The 24 static rules and separately scoped live-context AIG-PB001 are correctly distinguished. No VERIFIED LOCAL RELEASE CANDIDATE or production-ready designation is warranted.

NEXT SAFE ACTION: Publish this frozen source and its freshly executed evidence under the intended immutable non-release archive tag, inspect actual exact-head remote CI/artifact results, and proceed to the next product independently while preserving unique branch work.
