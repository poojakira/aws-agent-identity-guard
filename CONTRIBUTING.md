> **READ [LICENSE](LICENSE) BEFORE COPYING OR CHANGING ANYTHING.** This is an owner-maintained, proprietary repository. **Unsolicited code/documentation contributions are not accepted.** The development instructions below apply **only to people who have received prior written authorization** from Pooja Kiran. Public viewing/forking under GitHub's Terms, applicable law, third-party rights, and prior valid licenses remain unaffected. Any accepted external work requires an agreed written copyright license or assignment; a PR alone does not transfer ownership. For permission contact poojakiranbhardwaj@gmail.com.

# Authorized development

These instructions apply only to contributors covered by the written authorization above. Read [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md); a PR alone does not transfer rights.

Use [README development setup](README.md#develop-and-verify) and the clean-source studio verifier. The canonical rules live in `scanner.py`, optional collection/completeness in `live_scanner.py`, CLI/export in `cli.py`, rule-based suggestions in `remediate.py`, and browser parsing/evidence in `studio/`. Trust-policy checks belong to `scan_trust_policy`, not an invented separate rules API.

Before proposing a rule change, document its supported pattern and counter-context, choose an unused ID, preserve existing severities/thresholds unless a reviewed semantic correction requires otherwise, and add positive/negative tests. Keep 24 static IDs distinct from the live-context AIG-PB001 rule. Findings must not claim effective grants or exploitability from incomplete context.

Run complete regression, browser/schema/export, lint/format/type/security, package and existing performance gates at the actual candidate. `tests/test_live_scanner.py` uses mocked AWS; its passing tests do not establish live-account validation. The separate delegated-credentials demo is also mocked and needs its explicit test command. Record missing prerequisites/skips, exact source and out-of-tree evidence; never copy an older green count into a new-head headline.

Update current task/API/threat/operations/evidence docs in the same series, preserve legal/history records with context, and use synthetic inputs. Default merge, package/container release, AWS resources, external validation or notifications are separate reviewed actions. Preserve active/unique branches and follow [the evidence/release policy](docs/EVIDENCE.md).
