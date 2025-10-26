# ADR 0001: Repository Structure Modernization

## Status

Accepted

## Context

The project accumulated ad-hoc tooling and test layouts that made onboarding and
automation inconsistent. Scripts lived as Python utilities, tests were embedded
inside the source tree, and CI could not easily mirror local workflows.

## Decision

Normalize the repository around a canonical layout:

- Introduce a task-oriented `scripts/` toolbelt with Bash and PowerShell shims.
- Mirror the Python package hierarchy under `tests/unit` and centralize
  fixtures.
- Add metadata (`project.yaml`, `.tool-versions`, `.env.example`) to describe
  environments and service entrypoints.
- Standardize automation via a unified `Makefile`, updated CI pipeline, and
  SBOM/security scripts.

## Consequences

- Developers have a single entry point (`make bootstrap`, `make check`) that
  reproduces CI.
- Documentation and tooling now advertise the supported runtimes and commands.
- Future work can populate `tests/e2e`, `infra/`, and `configs/` without
  altering existing conventions.
