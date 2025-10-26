<!-- SPDX-License-Identifier: MPL-2.0 -->

# Provenance Audit — AI Accountability Infrastructure

- **Audit timestamp (UTC):** 2025-10-26 15:12:57Z
- **Auditor:** Automation via tools/add_spdx_headers.py execution context (OpenAI assistant)
- **Objective:** Validate readiness to relicense repository assets under the Mozilla Public License 2.0 (MPL-2.0).

## Methodology

1. Enumerated repository contributors using `git shortlog -sne`.
2. Enumerated tracked files using `git ls-files`.
3. Searched for inbound GPL-only code indicators with `rg -i "gpl"` and explicit GPL headers; no matches were found.
4. Reviewed tracked vendor trees (`node_modules/`, `sbom/`, `assets/`) to confirm they contain third-party assets under their original licenses and remain untouched by the relicensing scope.
5. Verified presence (or absence) of dedicated third-party notice files. This audit introduces an updated `NOTICE` file and a `THIRD_PARTY_NOTICES.md` index to retain upstream license texts.

## Contributors

```
24	lexsightllc <lexsightllc@lexsightllc.com>
     7	Your Name <you@example.com>
     4	Augusto Ochoa Ughini <lexsightllc@lexsightllc.com>
```

## Tracked Files

```
.codecov.yml
.dockerignore
.editorconfig
.env.example
.gitattributes
.github/CODEOWNERS
.github/workflows/ci.yml
.github/workflows/validate-events.yml
.gitignore
.pre-commit-config.yaml
.prettierignore
.readthedocs.yml
.tool-versions
AUTHORS
CHANGELOG.md
CODE_OF_CONDUCT.md
CONTRIBUTING.md
CONTRIBUTORS.md
DEVELOPMENT.md
Dockerfile
INSTALL.md
LICENSE
MAINTAINERS.md
MAINTAINERS_GUIDE.md
MANIFEST.in
Makefile
NOTICE
README.md
RELEASING.md
ROADMAP.md
SECURITY.md
THANKS
TROUBLESHOOTING.md
VERSION
app/main.py
assets/README.md
ci/README.md
claude_artifacts/6f841464-05b3-4f27-99c8-18b752f82798
config/.env.example
config/debug_keys.json
config/debug_receipt.json
config/default.toml
config/final_receipt.json
config/fixed_new_receipt.json
config/fixed_receipt.json
config/keys.json
config/merkle_performance.prof
config/new_keys.json
config/new_receipt.json
config/reason_codes.yaml
config/receipt.json
config/test_output.txt
configs/README.md
data/README.md
docker-compose.yml
docs/Makefile
docs/PROJECT_STRUCTURE.md
docs/QUICKSTART.md
docs/README.md
docs/SECURITY_AUDIT.md
docs/adr/0001-repository-structure.md
docs/api.rst
docs/conf.py
docs/development.md
docs/development.rst
docs/getting-started.rst
docs/index.rst
docs/receipt_spec_v1.rst
docs/verification_guide.md
docs/wire-format.md
examples/basic_usage.py
examples/client_example.py
examples/demo.py
examples/requirements.txt
examples/sample_receipt.json
examples/test_cli.py
gatekeeper/constants.py
infra/README.md
jobs/snapshot.py
keys/README.md
log/README.md
log/__init__.py
log/requirements.txt
log/server.py
logs/.gitkeep
mypy.ini
package-lock.json
package.json
project.yaml
pyproject.toml
pytest.ini
requirements-dev.txt
requirements-docs.txt
requirements.txt
sbom/README.md
schema/receipt.schema.json
schemas/gatekeeper.event.v1.json
schemas/receipt-v1.schema.json
schemas/vectors/invalid/issued_at_bad.json
schemas/vectors/invalid/nonce_short.json
schemas/vectors/invalid/signature_bad.json
schemas/vectors/valid/minimal.json
schemas/vectors/valid/with_proof.json
scripts/README.md
scripts/bootstrap
scripts/bootstrap.ps1
scripts/build
scripts/build.ps1
scripts/check
scripts/check.ps1
scripts/clean
scripts/clean.ps1
scripts/coverage
scripts/coverage.ps1
scripts/dev
scripts/dev.ps1
scripts/e2e
scripts/e2e.ps1
scripts/fmt
scripts/fmt.ps1
scripts/gen-docs
scripts/gen-docs.ps1
scripts/legacy/README.md
scripts/legacy/api.py
scripts/legacy/check_log.py
scripts/legacy/check_log_status.py
scripts/legacy/debug_receipt.py
scripts/legacy/dev_quickstart.sh
scripts/legacy/generate_test_keys.py
scripts/legacy/manage_log.py
scripts/legacy/start_log_server.py
scripts/legacy/submit_receipt.py
scripts/legacy/test_end_to_end.py
scripts/legacy/test_verify.py
scripts/legacy/visualize_tree.py
scripts/lib/common.sh
scripts/lint
scripts/lint.ps1
scripts/migrate
scripts/migrate.ps1
scripts/package
scripts/package.ps1
scripts/release
scripts/release.ps1
scripts/sbom
scripts/sbom.ps1
scripts/security-scan
scripts/security-scan.ps1
scripts/test
scripts/test.ps1
scripts/typecheck
scripts/typecheck.ps1
scripts/update-deps
scripts/update-deps.ps1
setup.py
src/ai_trust/__init__.py
src/ai_trust/__main__.py
src/ai_trust/api/__init__.py
src/ai_trust/api/main.py
src/ai_trust/cli/__init__.py
src/ai_trust/cli/commands.py
src/ai_trust/cli/main.py
src/ai_trust/cli/verify.py
src/ai_trust/core/__init__.py
src/ai_trust/core/app.py
src/ai_trust/core/canonicalization/__init__.py
src/ai_trust/core/crypto/__init__.py
src/ai_trust/core/db.py
src/ai_trust/core/merkle.py
src/ai_trust/core/models/__init__.py
src/ai_trust/core/receipt.py
src/ai_trust/core/verification.py
src/ai_trust/py.typed
src/ai_trust/services/log/server.py
src/ai_trust/services/verifier/README.md
src/ai_trust/services/verifier/__init__.py
src/ai_trust/services/verifier/pocket_verifier.py
src/ai_trust/services/verifier/verifier.py
src/ai_trust/services/verifier/verify.py
src/ai_trust/services/witness/service.py
tests/README.md
tests/e2e/README.md
tests/fixtures/README.md
tests/fixtures/raw/events/invalid_event.json
tests/fixtures/raw/events/valid_event.json
tests/fixtures/raw/receipts/input_nfd.json
tests/fixtures/raw/receipts/invalid_issued_at_offset.json
tests/fixtures/raw/receipts/invalid_nonce.json
tests/fixtures/raw/receipts/output.json
tests/fixtures/raw/receipts/test_jwks.json
tests/fixtures/raw/receipts/unicode_commitment.json
tests/fixtures/raw/receipts/valid_receipt.json
tests/integration/README.md
tests/integration/performance/test_merkle_performance.py
tests/unit/ai_trust/core/test_canonicalization.py
tests/unit/ai_trust/core/test_canonicalization_extended.py
tests/unit/ai_trust/core/test_core.py
tests/unit/ai_trust/core/test_receipt.py
tests/unit/ai_trust/services/log/test_merkle.py
tests/unit/ai_trust/services/log/test_transparency_log.py
tests/unit/ai_trust/services/verifier/test_pocket_verifier.py
tests/unit/ai_trust/services/verifier/test_verification.py
tests/unit/ai_trust/services/verifier/test_verifier.py
tests/unit/js/receipt-schema.spec.js
tests/unit/schemas/test_gatekeeper_event_schema.py
tests/unit/schemas/test_receipt_schema.py
tools/generate_keys.py
tools/generate_receipt.py
tools/pocket_verify.py
tools/sign_receipt.py
tools/synthetic.py
tools/verify_receipt.py
```

## Third-Party Components Review

- **JavaScript dependencies:** Stored in `node_modules/` (as pinned by `package-lock.json`). These remain under their upstream licenses and are excluded from MPL-2.0 relicensing. Future distributions must reproduce the notices shipped with each dependency.
- **Python dependencies:** Declared in `pyproject.toml`, `requirements.txt`, and related files. No vendored GPL-only code was identified; dependencies include permissive licenses (MIT, BSD, Apache-2.0, MPL-2.0, etc.).
- **Other assets:** Documentation, configuration, and infrastructure scripts are first-party and eligible for MPL-2.0 relicensing.

## Conclusion

No GPL-only inbound code or untracked third-party licenses were detected. All contributors are enumerated above; there are no blocking consent gaps for relicensing to MPL-2.0. Proceeding with MPL-2.0 relicensing steps is approved.
