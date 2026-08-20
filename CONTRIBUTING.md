# Contributing to AWS Agent Identity Guard

Thank you for considering contributing to AWS Agent Identity Guard! This document provides guidelines and instructions to help you get started.

## Table of Contents

- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing Requirements](#testing-requirements)
- [PR Process](#pr-process)
- [Security Policy Testing](#security-policy-testing)
- [Architecture Overview](#architecture-overview)

## Development Setup

### Prerequisites

- Python 3.10 or later
- Git
- (Optional) AWS CLI configured for integration tests

### Getting Started

```bash
# Clone the repository
git clone https://github.com/poojakira/aws-agent-identity-guard.git
cd aws-agent-identity-guard

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install in development mode with all dev dependencies
pip install -e ".[dev]"

# Verify installation
aws-agent-identity-guard --help
```

### IDE Setup

We recommend VS Code or PyCharm with:
- Ruff extension for linting/formatting
- Pyright extension for type checking

## Code Style

We enforce consistent code style through automated tooling:

- **Formatter**: Ruff (line length 100)
- **Linter**: Ruff with rules: E, F, W, I, UP, B, SIM, TCH
- **Type Checker**: Pyright in standard mode
- **Target**: Python 3.10+

### Key conventions

1. All public functions and classes must have docstrings (Google style).
2. Use `from __future__ import annotations` in all modules.
3. Prefer `pathlib.Path` over `os.path`.
4. Use dataclasses or Pydantic models for structured data.
5. Keep modules focused — one responsibility per file.
6. Import ordering: stdlib → third-party → local (enforced by ruff `I` rule).

### Running linters locally

```bash
# Format code
ruff format src/ tests/

# Lint and auto-fix
ruff check --fix src/ tests/

# Type check
pyright src/
```

## Testing Requirements

All contributions must include appropriate tests:

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=aws_agent_identity_guard --cov-report=term-missing

# Run specific test file
pytest tests/test_policy_engine.py

# Run tests matching a pattern
pytest -k "test_deny_wildcard"
```

### Test Guidelines

1. **Unit tests are mandatory** for all new functions and classes.
2. **Integration tests** are required for AWS service interactions (use `moto` for mocking).
3. **Policy tests** must cover both allow and deny scenarios.
4. Maintain **>90% code coverage** on new code.
5. Tests must pass on Python 3.10, 3.11, 3.12, and 3.13.
6. Use `pytest` fixtures for shared setup; avoid test interdependencies.
7. Name test files `test_<module>.py` and test functions `test_<behavior>`.

### Test Structure

```
tests/
├── test_policy_engine.py      # Policy evaluation logic
├── test_attack_path.py        # Attack path analysis
├── test_privilege_escalation.py  # Priv-esc detection
├── test_runtime_auth.py       # Runtime authorization
├── test_sarif_output.py       # SARIF report generation
├── test_cli.py                # CLI commands
└── fixtures/                  # Shared test data
    ├── policies/
    └── iam_configs/
```

## PR Process

1. **Fork and branch**: Create a feature branch from `main` (e.g., `feat/add-scp-support`).
2. **Small, focused PRs**: Each PR should address a single concern.
3. **Commit messages**: Use conventional commits format:
   - `feat:` new features
   - `fix:` bug fixes
   - `docs:` documentation
   - `test:` test additions/changes
   - `refactor:` code restructuring
   - `ci:` CI/CD changes
4. **PR description**: Include:
   - Summary of changes
   - Link to related issue (if any)
   - Testing performed
   - Breaking changes (if any)
5. **Checks must pass**: All CI checks (lint, type check, tests) must be green.
6. **Review required**: At least one maintainer approval before merge.
7. **Squash merge**: PRs are squash-merged to maintain a clean history.

## Security Policy Testing

Since this project enforces security policies, extra care is needed when modifying policy logic:

### Writing Policy Tests

```python
import pytest
from aws_agent_identity_guard.policy_engine import PolicyEngine

def test_deny_iam_wildcard():
    """Verify that wildcard IAM access is always denied."""
    engine = PolicyEngine(policy_path="policies/default.yaml")
    result = engine.evaluate(
        action="iam:CreateRole",
        resource="*",
        context={"environment": "production"}
    )
    assert result.decision == "DENY"
    assert result.rule_id == "DENY-IAM-WILDCARD"
```

### Policy Test Checklist

- [ ] Test each rule in isolation
- [ ] Test rule interactions (multiple rules matching)
- [ ] Test with both matching and non-matching inputs
- [ ] Test severity levels are correctly assigned
- [ ] Test that `require_approval` rules trigger approval flow
- [ ] Test custom policies override defaults correctly
- [ ] Test malformed policy files produce clear errors
- [ ] Verify SARIF output includes all findings

### Testing Custom Policies

```bash
# Validate a policy file
aws-agent-identity-guard validate-policy policies/custom.yaml

# Dry-run policy against a role
aws-agent-identity-guard lint --policy policies/production.yaml --role-arn arn:aws:iam::123456789012:role/AgentRole
```

## Architecture Overview

```
src/aws_agent_identity_guard/
├── __init__.py                 # Package entry point
├── cli.py                      # CLI interface (click/argparse)
├── api.py                      # REST API server (uvicorn)
├── models.py                   # Core data models
├── policy_engine.py            # Policy loading and evaluation
├── policy_loader.py            # YAML policy file parsing
├── iam_analyzer.py             # IAM policy analysis
├── attack_path.py              # Attack path graph analysis
├── privilege_escalation.py     # Privilege escalation detection
├── runtime_authorizer.py       # Runtime authorization decisions
├── risk_scorer.py              # Risk scoring engine
├── sarif_formatter.py          # SARIF output generation
├── cloudtrail_monitor.py       # CloudTrail event processing
└── utils/
    ├── aws.py                  # AWS SDK helpers
    ├── cache.py                # Caching utilities
    └── logging.py              # Structured logging
```

### Key Design Principles

1. **Offline-first**: Core analysis works without AWS credentials using policy files.
2. **Layered evaluation**: Policies are evaluated in order — deny > require_approval > warn > audit > allow.
3. **Extensible rules**: New rule types can be added by extending the rule evaluator.
4. **SARIF-native**: All findings are modeled as SARIF results for CI/CD integration.
5. **Zero runtime dependencies**: Core package only requires PyYAML; AWS/server deps are optional.

### Data Flow

```
IAM Policy (JSON/YAML) → Policy Loader → Policy Engine → Evaluation Result
                                              ↕
                                     Security Rules (YAML)
                                              ↓
                                     SARIF Report / API Response
```

## Questions?

Open an issue on GitHub or reach out to the maintainers. We're happy to help!
