# Contributing to AWS Agent Identity Guard

We welcome contributions. This document covers development setup, testing, style guidelines, and the PR process.

---

## Development Setup

### Prerequisites

- Python 3.10+ (3.12 recommended)
- [uv](https://github.com/astral-sh/uv) package manager (recommended) or pip
- Git

### Setup

```bash
# Clone
git clone https://github.com/aws/agent-identity-guard.git
cd agent-identity-guard

# Create virtual environment
uv venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install in editable mode with dev dependencies
uv pip install -e ".[dev]"

# Verify
pytest tests/ -v --tb=short
```

### Running Locally

```bash
# Start the API server
uvicorn aws_agent_identity_guard.api:app --reload --port 8000

# Run the demo
python -m demo.run_demo
```

---

## Testing

### Running Tests

```bash
# All tests
pytest tests/ -v

# Specific module
pytest tests/test_authorization.py -v

# With coverage
pytest tests/ --cov=src/aws_agent_identity_guard --cov-report=term-missing

# Fast (skip slow integration tests)
pytest tests/ -m "not slow"
```

### Test Categories

| Directory / File | Purpose |
|------------------|---------|
| `tests/test_models.py` | Data model validation |
| `tests/test_policy_engine.py` | Policy evaluation logic |
| `tests/test_risk_engine.py` | Risk scoring accuracy |
| `tests/test_authorization.py` | End-to-end authorization |
| `tests/test_attack_paths.py` | Escalation chain detection |
| `tests/test_escalation.py` | Escalation pattern matching |
| `tests/test_adversarial.py` | Adversarial inputs and edge cases |
| `tests/test_resilience.py` | Fault tolerance and recovery |
| `tests/test_scanner.py` | Static policy scanning |
| `tests/benchmarks/` | Performance benchmarks |

### Writing Tests

- Every new feature needs tests
- Every bug fix needs a regression test
- Target 90%+ coverage for new code
- Use descriptive test names: `test_deny_when_risk_exceeds_threshold`
- Use fixtures for common setup (see `conftest.py`)

---

## Code Style

### Formatting

We use [ruff](https://github.com/astral-sh/ruff) for linting and formatting.

```bash
# Check
ruff check src/ tests/
ruff format --check src/ tests/

# Fix
ruff check --fix src/ tests/
ruff format src/ tests/
```

### Style Guidelines

- Type hints on all function signatures
- Docstrings on all public functions and classes
- No wildcard imports
- Prefer dataclasses for value objects
- Use enums instead of string constants
- Logging via `logging.getLogger(__name__)`
- No print statements in library code
- Constants in UPPER_SNAKE_CASE
- Private functions prefixed with underscore

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add time-window condition to policy engine
fix: handle empty policy file without crash
docs: update API reference with approval endpoints
test: add escalation detection edge cases
refactor: extract risk dimension calculation
chore: update dependencies
```

---

## PR Process

### Before Submitting

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Make your changes
3. Run the full test suite:
   ```bash
   pytest tests/ -v
   ```
4. Run linting:
   ```bash
   ruff check src/ tests/
   ruff format --check src/ tests/
   ```
5. Update documentation if needed
6. Write a clear commit message

### PR Requirements

- [ ] Tests pass
- [ ] Linting passes
- [ ] Coverage does not decrease
- [ ] Documentation updated (if applicable)
- [ ] No secrets or credentials committed
- [ ] Changelog entry added (for user-facing changes)

### Review Process

1. Open PR against `main`
2. CI runs automatically (tests, lint, security scan)
3. At least one maintainer review required
4. Address review feedback
5. Squash merge once approved

### What We Look For

- Correct behavior (tests prove it)
- Clean code (readable, maintainable)
- Performance awareness (no unnecessary allocations in hot paths)
- Security awareness (input validation, no injection vectors)
- Documentation (API changes documented, complex logic commented)

---

### Data Flow

**Do not open a public issue for security vulnerabilities.**

Instead, report security issues to: security@agent-identity-guard.dev

Or use GitHub's private vulnerability reporting feature.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge within 48 hours and provide a fix timeline within 7 days.

See [SECURITY.md](SECURITY.md) for our full security policy.

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
