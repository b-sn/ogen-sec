SHELL := /bin/bash

GO ?= go
BIN_DIR := $(CURDIR)/bin
OGEN_VERSION := v1.24.0
GOLANGCI_LINT_VERSION := v2.13.2
OGEN := $(BIN_DIR)/ogen
GOLANGCI_LINT := $(BIN_DIR)/golangci-lint
SCHEMA ?= ./securitygen/testdata/integration/openapi.yaml
OGEN_TARGET ?= ./.tmp/ogen
OGEN_CONFIG ?= ./securitygen/testdata/integration/ogen.yml

.PHONY: tools ogen-install golangci-lint-install ogen schema-validate lint test check

tools: ogen-install golangci-lint-install

ogen-install:
	@mkdir -p "$(BIN_DIR)"
	@if [ -x "$(OGEN)" ] && "$(OGEN)" -version | grep -q "ogen version $(OGEN_VERSION) "; then \
		echo "Using $(OGEN)"; \
	else \
		GOBIN="$(BIN_DIR)" $(GO) install github.com/ogen-go/ogen/cmd/ogen@$(OGEN_VERSION); \
	fi

golangci-lint-install:
	@mkdir -p "$(BIN_DIR)"
	@if [ -x "$(GOLANGCI_LINT)" ] && "$(GOLANGCI_LINT)" --version | grep -q "version $(GOLANGCI_LINT_VERSION) "; then \
		echo "Using $(GOLANGCI_LINT)"; \
	else \
		GOBIN="$(BIN_DIR)" $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	fi

# Generate ogen's API package for the selected schema. The default output is
# intentionally transient; committed fixtures contain only source schemas and
# securitygen golden files.
ogen: ogen-install
	@mkdir -p "$(OGEN_TARGET)"
	$(OGEN) --target "$(OGEN_TARGET)" --clean $(if $(strip $(OGEN_CONFIG)),--config "$(OGEN_CONFIG)") "$(SCHEMA)"

# ogen validates OpenAPI input as part of generation. Use a disposable target
# so validation never changes a checked-in fixture.
schema-validate: ogen-install
	@target="$$(mktemp -d)"; \
	trap 'rm -rf "$$target"' EXIT; \
	for schema in securitygen/testdata/integration/*/openapi.yaml securitygen/testdata/integration/openapi.yaml; do \
		[ -f "$$schema" ] || continue; \
		args=(--target "$$target/$${schema%/*}" --clean); \
		if [ "$$schema" = "securitygen/testdata/integration/openapi.yaml" ]; then args+=(--config securitygen/testdata/integration/ogen.yml); fi; \
		$(OGEN) "$${args[@]}" "$$schema"; \
	done

lint: golangci-lint-install
	$(GOLANGCI_LINT) run ./...

# Integration tests invoke the pinned ogen binary to generate each fixture
# before comparing securitygen output to its golden file.
test: ogen-install
	OGEN_BIN="$(OGEN)" $(GO) test ./...

check: lint test
