# AI Trust Infrastructure

A framework for transparent and verifiable AI operations.

## Features

- Cryptographic receipts for AI model outputs
- Transparency logging
- Witness services
- API gateway for integration

## Developer Tasks

Use the scripts in `scripts/` (or the equivalent `Makefile` targets) to manage the project lifecycle.

| Task | Script | Description |
| --- | --- | --- |
| Bootstrap | `scripts/bootstrap` / `make bootstrap` | Create the virtual environment, install Python and Node dependencies, and configure pre-commit hooks. |
| Development server | `scripts/dev` / `make dev` | Launch the FastAPI development server with hot reload. |
| Format | `scripts/fmt` / `make fmt` | Apply Black, isort, and Ruff fixes across the repository. |
| Lint | `scripts/lint` / `make lint` | Run Ruff, Black (check mode), and isort (check mode); invokes Node linters when defined. |
| Type check | `scripts/typecheck` / `make typecheck` | Run mypy in strict mode and any configured TypeScript checks. |
| Unit tests | `scripts/test` / `make test` | Execute Python unit tests via pytest and JSON schema validation tests via Node. |
| Integration tests | `scripts/e2e` / `make e2e` | Execute end-to-end pytest suites when present. |
| Coverage | `scripts/coverage` / `make coverage` | Run pytest with coverage thresholds and produce `coverage.xml`. |
| Build | `scripts/build` / `make build` | Build Python distributions and run any configured frontend build. |
| Package | `scripts/package` / `make package` | Produce distributable Python artifacts (wheel and sdist) and optional npm packages. |
| Release | `scripts/release` / `make release` | Build artifacts, run Twine checks, and optionally create a signed git tag. |
| Update dependencies | `scripts/update-deps` / `make update-deps` | Update pinned dependencies via `pip-compile` and `npm update`. |
| Security scan | `scripts/security-scan` / `make security-scan` | Run `pip-audit`, `npm audit`, and optional Trivy scans. |
| SBOM | `scripts/sbom` / `make sbom` | Generate CycloneDX SBOMs for Python and Node dependencies in `sbom/`. |
| Documentation | `scripts/gen-docs` / `make gen-docs` | Build the Sphinx documentation into `docs/_build/html`. |
| Migrations | `scripts/migrate` / `make migrate` | Stub indicating that no schema migrations are currently defined. |
| Clean | `scripts/clean` / `make clean` | Remove build artifacts, caches, and generated reports. |
| Full check | `scripts/check` / `make check` | Run linting, type checking, tests, coverage enforcement, security scans, and SBOM generation. |

### Quick start

```bash
make bootstrap
make check
```

## License

Apache 2.0
