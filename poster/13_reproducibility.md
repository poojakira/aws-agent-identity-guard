# Reproduce the Work - Poster 02

**Repository:** `github.com/poojakira/aws-agent-identity-guard`  
**Verified code snapshot:** `229605c9c53068f4c0d7116d67554d19afe30183`  
**CI run:** `37170669504`

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard
git checkout 229605c9c53068f4c0d7116d67554d19afe30183
python -m pip install -e ".[dev]"
pytest tests/ -q
python benchmarks/perf_gate.py
```

Expected CI test evidence: **243 collected, 240 passed, 3 skipped**.

Current CI performance evidence: **0.8397 ms p95**, **2,573 policies/sec** on the repository's synthetic 500-policy gate.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
