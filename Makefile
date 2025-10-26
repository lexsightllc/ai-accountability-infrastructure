SHELL := /bin/bash
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: bootstrap dev lint fmt typecheck test e2e coverage build package release update-deps security-scan sbom gen-docs migrate clean check docs

bootstrap:
$(ROOT)/scripts/bootstrap $(ARGS)

dev:
$(ROOT)/scripts/dev $(ARGS)

lint:
$(ROOT)/scripts/lint $(ARGS)

fmt:
$(ROOT)/scripts/fmt $(ARGS)

typecheck:
$(ROOT)/scripts/typecheck $(ARGS)

test:
$(ROOT)/scripts/test $(ARGS)

e2e:
$(ROOT)/scripts/e2e $(ARGS)

coverage:
$(ROOT)/scripts/coverage $(ARGS)

build:
$(ROOT)/scripts/build $(ARGS)

package:
$(ROOT)/scripts/package $(ARGS)

release:
$(ROOT)/scripts/release $(ARGS)

update-deps:
$(ROOT)/scripts/update-deps $(ARGS)

security-scan:
$(ROOT)/scripts/security-scan $(ARGS)

sbom:
$(ROOT)/scripts/sbom $(ARGS)

gen-docs:
$(ROOT)/scripts/gen-docs $(ARGS)

docs: gen-docs

migrate:
$(ROOT)/scripts/migrate $(ARGS)

clean:
$(ROOT)/scripts/clean $(ARGS)

check:
$(ROOT)/scripts/check $(ARGS)
