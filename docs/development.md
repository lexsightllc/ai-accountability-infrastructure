<!-- SPDX-License-Identifier: MPL-2.0 -->

# Development Guide

## Project Structure
ai-trust/
├── config/               # Configuration files
├── data/                 # Data files (not versioned)
├── docs/                 # Documentation
├── examples/             # Example code
├── keys/                 # Cryptographic keys (not versioned)
├── logs/                 # Log files (not versioned)
├── scripts/              # Utility scripts
├── src/                  # Source code
│   └── ai_trust/         # Main package
│       ├── api/          # API endpoints
│       ├── cli/          # Command-line interface
│       ├── core/         # Core functionality
│       └── services/     # Backend services
└── tests/                # Tests
    ├── integration/      # Integration tests
    └── unit/             # Unit tests

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/ai-trust.git
   cd ai-trust
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install the package in development mode:
   ```bash
   pip install -e '.[dev,server,crypto]'
   ```
4. Set up pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Testing

Run the test suite:

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=ai_trust --cov-report=term-missing
```

## Code Style

We use:

- Black for code formatting
- isort for import sorting
- flake8 for linting
- mypy for type checking

Run all code quality checks:

```bash
black .
isort .
flake8
mypy .
```

## Documentation

Build the documentation:

```bash
cd docs
make html
```

The documentation will be available in docs/_build/html/.
