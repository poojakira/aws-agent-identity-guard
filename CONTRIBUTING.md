# Contributing

Thank you for contributing to AWS Agent Identity Guard.

## Development Setup

```bash
git clone https://github.com/poojakira/aws-agent-identity-guard
cd aws-agent-identity-guard
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests (static rules only — no AWS credentials required)
pytest tests/test_scanner.py -v

# Live scanner tests (requires moto; no real AWS calls)
pytest tests/test_live_scanner.py -v

# All tests
pytest -v
```

## Linting and Formatting

```bash
ruff check src tests
ruff format src tests
```

## Static Security Scan

```bash
bandit -r src/ -ll
pip-audit --skip-editable
```

## Adding a New Rule

1. Add a constant or helper in `scanner.py` if needed.
2. Add the rule logic in `scan_policy_document()` or `scan_trust_policy()`.
3. Use the next available rule ID (`AIG-NNN` for identity policies, `AIG-TP-NNN` for trust policies).
4. Add a test in `tests/test_scanner.py` with at least one triggering fixture and one non-triggering fixture.
5. Document the rule in `SECURITY_AUDIT.md` under "New Rules Added."

## Pull Request Guidelines

- One PR per feature or bug fix.
- Tests must pass on Python 3.10, 3.11, and 3.12.
- No new runtime dependencies without justification.
- README updates must match the implementation.
- Do not weaken existing assertions or add `# noqa` without explanation.

## Security Issues

See [SECURITY.md](SECURITY.md) for vulnerability reporting. Do not open public issues for security bugs.
