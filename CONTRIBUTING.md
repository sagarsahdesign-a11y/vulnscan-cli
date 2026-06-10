# Contributing to cvemap

First off — thank you for considering contributing to cvemap! 🎉  
Every contribution, no matter how small, helps make this tool better for the security community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting a PR](#submitting-a-pr)
- [Release Process](#release-process)

---

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/).  
Be respectful, constructive, and inclusive. Security is for everyone.

---

## How to Contribute

### Reporting Bugs

Use the [bug report template](https://github.com/sagarsahdesign-a11y/vulnscan-cli/issues/new?template=bug_report.yml).  
Please include: cvemap version, Python version, nmap version, OS, and the exact command + output.

### Requesting Features

Use the [feature request template](https://github.com/sagarsahdesign-a11y/vulnscan-cli/issues/new?template=feature_request.yml).

### Code Contributions

1. Check [open issues](https://github.com/sagarsahdesign-a11y/vulnscan-cli/issues) for `good first issue` or `help wanted` labels
2. Comment on an issue to claim it before starting work
3. Fork → Branch → Code → Test → PR

---

## Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_FORK/vulnscan-cli.git
cd vulnscan-cli

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
# .venv\Scripts\activate     # Windows

# 3. Install in editable mode with dev dependencies
pip install -e ".[dev]"

# 4. Set up your .env
cp .env.example .env
# Add your NVD API key to .env

# 5. Verify setup
cvemap version
pytest
```

---

## Project Structure

```
cvemap/
├── cvemap/              # Main Python package
│   ├── __init__.py      # Version, public API
│   ├── cli.py           # Argparse entry point + command handlers
│   ├── scanner.py       # Nmap wrapper, ScanResult/PortInfo models
│   ├── cve_lookup.py    # NIST NVD API v2.0 client + CVEResult model
│   ├── reporter.py      # JSON + HTML report generation
│   └── utils.py         # Config, logging, rate limiter, helpers
├── templates/
│   └── report.html      # Jinja2 HTML report template
├── tests/
│   ├── conftest.py      # Shared fixtures
│   ├── test_scanner.py
│   ├── test_cve_lookup.py
│   └── test_reporter.py
├── .github/
│   ├── workflows/ci.yml
│   └── ISSUE_TEMPLATE/
├── pyproject.toml       # Modern packaging + tool config
├── requirements.txt
└── requirements-dev.txt
```

**Key design principles:**
- `scanner.py` has **zero network calls** beyond nmap — it's pure nmap wrapping
- `cve_lookup.py` has **zero nmap dependency** — it's pure HTTP
- `reporter.py` has **no I/O side effects** in `build_report_data()` — it just builds a dict
- All side effects (file writes, HTTP calls) are isolated and easily mockable in tests

---

## Coding Standards

We use automated tooling — make sure these pass before opening a PR:

```bash
# Format code
black cvemap/ tests/
isort cvemap/ tests/

# Lint
ruff check cvemap/ tests/

# Type check
mypy cvemap/ --ignore-missing-imports
```

**Style guidelines:**
- Line length: **99 characters**
- Docstrings: **Google style** for public functions/classes
- Type hints: Required for all public function signatures
- No bare `except:` — always catch specific exceptions
- Use `get_logger(__name__)` for logging (not `print()` for diagnostic output)
- Use `console.print()` (rich) for user-facing terminal output

---

## Testing

```bash
# Run all tests
pytest

# Run with coverage (must be ≥ 70%)
pytest --cov=cvemap --cov-report=term-missing

# Run a single test file
pytest tests/test_cve_lookup.py -v

# Run tests matching a keyword
pytest -k "test_search" -v
```

**Testing rules:**
- All NVD API calls **must be mocked** (`unittest.mock.patch`)
- All nmap calls **must be mocked**
- Tests must pass **without root, without nmap installed, without internet access**
- New features need at least one test for the happy path and one for error handling

---

## Submitting a PR

1. Create a branch: `git checkout -b feat/my-feature` or `fix/bug-description`
2. Make your changes — small, focused PRs are preferred over large ones
3. Add or update tests
4. Ensure CI checks pass locally:
   ```bash
   ruff check cvemap/ tests/ && black --check cvemap/ tests/ && pytest
   ```
5. Push and open a PR against the `main` branch
6. Fill in the PR template fully
7. Wait for review — we aim to respond within 48 hours

---

## Release Process

Maintainer-only:

```bash
# 1. Bump version in pyproject.toml and cvemap/__init__.py
# 2. Update CHANGELOG.md
git commit -am "chore: release v1.x.x"
git tag v1.x.x
git push origin main --tags

# 3. Create a GitHub Release
#    → CI automatically builds and publishes to PyPI via trusted publishing
```

---

Thank you for making cvemap better! 🚀
