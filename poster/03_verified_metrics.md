# Verified Metrics - Poster 02

**Code snapshot:** `229605c9c53068f4c0d7116d67554d19afe30183`  
**CI run:** https://github.com/poojakira/aws-agent-identity-guard/actions/runs/37170669504

| Metric | Cited snapshot value |
|---|---:|
| Tests collected | **243** |
| Tests passed | **240** |
| Tests skipped | **3** |
| Deterministic rule IDs | **25** |
| Synthetic-policy p95 | **0.8397 ms** |
| Synthetic-policy throughput | **2,573 policies/sec** |

The performance figures come from the cited CI performance gate over 500 synthetic policies. They are not production performance claims.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
