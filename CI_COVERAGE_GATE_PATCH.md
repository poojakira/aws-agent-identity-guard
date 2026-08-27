# CI Coverage Gate Patch Instructions

## Summary

Add a 90% code coverage gate to the CI pipeline to prevent coverage regressions.

## Change Required

In your existing CI workflow (e.g., `.github/workflows/ci.yml` or `.github/workflows/test.yml`), update the pytest command to enforce minimum coverage:

### Before

```yaml
- name: Run tests
  run: pytest tests/ --cov=aws_agent_identity_guard --cov-report=xml
```

### After

```yaml
- name: Run tests with coverage gate
  run: |
    pytest tests/ \
      --cov=aws_agent_identity_guard \
      --cov-report=xml \
      --cov-report=term-missing \
      --cov-fail-under=90
```

## Full CI Job Example

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          pip install -e ".[dev]"
          pip install pytest-cov

      - name: Run tests with coverage gate
        run: |
          pytest tests/ \
            --cov=aws_agent_identity_guard \
            --cov-report=xml \
            --cov-report=term-missing \
            --cov-fail-under=90

      - name: Upload coverage to Codecov
        if: matrix.python-version == '3.12'
        uses: codecov/codecov-action@v4
        with:
          files: coverage.xml
          fail_ci_if_error: false

  perf-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install package
        run: pip install -e .

      - name: Run performance gate
        run: python benchmarks/perf_gate.py --output perf-results.json

      - name: Upload perf results
        uses: actions/upload-artifact@v4
        with:
          name: perf-results
          path: perf-results.json
```

## pyproject.toml Configuration

Add these sections to `pyproject.toml` for consistent local and CI behavior:

```toml
[tool.pytest.ini_options]
addopts = "--cov=aws_agent_identity_guard --cov-fail-under=90 --cov-report=term-missing"
testpaths = ["tests"]

[tool.coverage.run]
source = ["aws_agent_identity_guard"]
branch = true

[tool.coverage.report]
fail_under = 90
show_missing = true
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "if __name__ == .__main__.",
    "if TYPE_CHECKING:",
    "raise NotImplementedError",
]
```

## Verification

After applying this patch, verify locally:

```bash
# Should pass (if coverage is >= 90%)
pytest tests/ --cov=aws_agent_identity_guard --cov-fail-under=90

# Check current coverage
pytest tests/ --cov=aws_agent_identity_guard --cov-report=term-missing
```

If coverage is below 90%, the new tests in `tests/test_coverage_boost.py` should help bridge the gap.
