<!-- SPDX-License-Identifier: MPL-2.0 -->

# Development Guide

This guide provides information for developers working on the AI Trust project.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/ai-trust.git
   cd ai-trust
   ```
3. Set up a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install development dependencies:
   ```bash
   pip install -e '.[dev,server,crypto]'
   ```
5. Set up pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Code Style

We use the following tools to maintain code quality:

- Black for code formatting
- isort for import sorting
- ruff for linting
- mypy for type checking

Run all code quality checks:

```bash
make lint
```

## Testing

Run the test suite:

```bash
make test
```

Run tests with coverage:

```bash
pytest --cov=ai_trust --cov-report=term-missing
```

## Documentation

Build the documentation:

```bash
cd docs
make html
```

The documentation will be available in docs/_build/html/.

## Pull Requests

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature
   ```
2. Make your changes
3. Run the test suite and fix any issues
4. Commit your changes:
   ```bash
   git commit -m "Add your feature"
   ```
5. Push to your fork:
   ```bash
   git push origin feature/your-feature
   ```
6. Open a pull request

## Code Review Process

- A maintainer will review your PR
- Address any feedback
- Once approved, your PR will be merged

## Release Process

1. Update the version in pyproject.toml
2. Update CHANGELOG.md
3. Create a new tag:
   ```bash
   git tag -a vX.Y.Z -m "Version X.Y.Z"
   git push origin vX.Y.Z
   ```
4. Create a new release on GitHub

## Getting Help

If you need help, please:

- Check the documentation
- Search the issue tracker
- Open a new issue if your problem isn't already reported
