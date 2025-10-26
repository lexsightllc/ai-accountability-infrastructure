<!-- SPDX-License-Identifier: MPL-2.0 -->

# Contributing to AI Trust

Thank you for your interest in contributing to AI Trust! We welcome contributions from everyone.

## Licensing Expectations

By submitting a contribution, you agree that it will be licensed under the [Mozilla Public License 2.0 (MPL-2.0)](LICENSE). We operate under inbound=outbound terms: we accept only contributions that you are able to license under MPL-2.0, and we will distribute those contributions under the same license. Please ensure that any third-party code you include retains its original license and associated notices in accordance with the repository [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.md).

## How to Contribute

1. **Report bugs**: File an issue if you find a bug
2. **Fix bugs**: Submit a pull request with your fix
3. **Add features**: Propose a new feature or implement an existing one
4. **Improve documentation**: Help us make the docs better
5. **Spread the word**: Tell others about AI Trust

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

## Making Changes

1. Create a new branch:
   ```bash
   git checkout -b feature/your-feature
   ```
2. Make your changes
3. Run the test suite:
   ```bash
   make test
   ```
4. Run code quality checks:
   ```bash
   make lint
   ```
5. Commit your changes:
   ```bash
   git commit -m "Add your feature"
   ```
6. Push to your fork:
   ```bash
   git push origin feature/your-feature
   ```
7. Open a pull request

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

We use pytest for testing. Run the test suite with:

```bash
make test
```

Write tests for new features and bug fixes. Aim for good test coverage.

## Documentation

Update the documentation when adding new features or changing existing ones. The documentation is in the `docs/` directory.

## Code Review Process

1. A maintainer will review your PR
2. Address any feedback
3. Once approved, your PR will be merged

## Reporting Issues

When reporting issues, please include:

- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details (Python version, OS, etc.)

## Code of Conduct

Please note that this project is released with a Contributor Code of Conduct. By participating in this project you agree to abide by its terms.

## License

By contributing, you agree that your contributions will be licensed under the project's LICENSE file.
