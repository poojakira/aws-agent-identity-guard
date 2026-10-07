# Project History and Repository Provenance

## Timeline distinction

This document deliberately separates **project development history** from **public GitHub repository history**.

- **Maintainer-recorded original project development:** Apr. 2025 - Sep. 2025
- **First reachable public GitHub commit on `main`:** 2026-08-01
- **First public commit:** `b4799d64eeefba1dfbced8cf8d303a6e07f18dbe`
- **Maintainer:** Pooja Kiran ([@poojakira](https://github.com/poojakira))

The first public GitHub commit records when the project entered the current public repository. It is **not, by itself, proof of when the underlying project work began**.

The earlier development period above is the maintainer's recorded project history. Work before the first public commit was performed outside the current public Git history and was later imported, consolidated, expanded, hardened, tested, or documented in this repository.

## Evidence status

Git directly proves the repository history from the first reachable public commit forward. It does not independently prove or disprove earlier local, private, academic, or otherwise pre-public development.

Where available, earlier chronology should be strengthened with independently timestamped artifacts such as cloud-drive version history, email attachments or correspondence, university/LMS records, private-repository history, preserved source archives, dated reports, diagrams, screenshots, notebooks, or test outputs.

No such artifact should be modified, recreated, or backdated merely to support a chronology claim.

## Evidence standard

This audit separates three different things:

1. **Git repository inception** — the earliest reachable commit on the default branch.
2. **Pre-Git source lineage** — accepted only when a dated artifact clearly refers to the same project or an identifiable direct precursor.
3. **Background dates** — course years, publication years, CVE/incident dates, dataset dates, framework versions, test timestamps, and copied changelog labels do **not** backdate a repository unless they directly prove the project's own existence.

Git history is preserved as historical evidence. It is not rewritten or backdated from later documents.

## Findings

- Connected Drive searches surfaced 2026 ASU/ARSP security research documents, but not a direct pre-2026 artifact naming this repository. They therefore do not justify an earlier repo year.

## Provenance conclusion

The directly verifiable conclusion from the current Git repository is that its **public GitHub history begins in 2026-08**.

That fact must not be conflated with project inception. The maintainer records the original development period as **Apr. 2025 - Sep. 2025**.

The correct interpretation is:

> The original project was developed during Apr.-Sep. 2025 and was later published/imported into the current public GitHub repository in Aug. 2026, where it was further verified, documented, and maintained.

Current test counts, coverage, rules, fixtures, features, CI controls, and other quantified claims remain tied to their own later verification snapshots. They should not be projected backward to the beginning of the project period unless a dated historical artifact supports that exact metric.

## Audit scope

Evidence considered in this pass included:

- reachable Git commit history on `main`;
- repository README, changelog, reports, and documentation;
- date-like labels in high-visibility files;
- course/project references where present;
- connected Drive metadata/search for exact or closely related project names;
- previously verified academic/publication evidence, used only as background unless a direct lineage could be established.

**Audit date:** 2026-09-21



## Clarification — 2026-10-07

An earlier version of this audit used wording such as **"earliest defensible year for this repository/project lineage: 2026."** That phrasing was too broad because it merged two different questions:

1. When does the current public Git repository history begin?
2. When did the underlying project work begin?

The corrected interpretation is:

- **Public Git repository history:** directly verifiable from 2026-08-01.
- **Maintainer-recorded project development:** Apr. 2025 - Sep. 2025.
- **Independent pre-Git verification:** should be cited when preserved external artifacts are available and inspected.

This clarification preserves the genuine Git history. It does not backdate commits, rewrite timestamps, or claim that today's implementation and metrics existed unchanged during the earlier project period.

## Expanded proof matrix

| Evidence source | What was checked | Result |
|---|---|---|
| Reachable Git history | Earliest reachable commit on `main` | **2026-08-01** — [`b4799d64eeef`](https://github.com/poojakira/aws-agent-identity-guard/commit/b4799d64eeefba1dfbced8cf8d303a6e07f18dbe) — `Initial AWS agent identity guard` |
| Repository files/docs | README, changelog, reports, embedded date labels, provenance files, and high-visibility docs | No dated file reviewed establishes this repository or a clearly identifiable direct precursor before **2026**. |
| Course/project references | Course codes, academic project references, publication links, and research-period references present in or connected to the repository | No course/publication reference reviewed proves this repository existed before **2026**. Earlier academic work remains a separate provenance track unless direct lineage is documented. |
| Internal evidence | Repository-local evidence files and previously audited connected-source metadata | Supports the documented 2026 development/research period; no direct pre-2026 same-project artifact was established. |
| Commit identity/history integrity | Historical author/committer objects and existing timestamps | Preserved as-is. No commits were backdated, timestamp-rewritten, or replaced to manufacture an older timeline. |

### Repository-specific evidence notes

- Connected Drive searches surfaced 2026 ASU/ARSP security research documents, but not a direct pre-2026 artifact naming this repository. They therefore do not justify an earlier repo year.

### Provenance confidence

**High for the mapped year (2026).** The reachable Git history is direct evidence. Any earlier year would require a dated source artifact that can be tied to this exact repository or a clearly identifiable direct precursor.

### History policy

This audit records provenance **without rewriting Git history**. If stronger pre-Git evidence is discovered later, document it as pre-Git lineage with the artifact date and source; do not alter historical commit timestamps.