SHELL := /bin/bash
NVM_DIR := $(HOME)/.nvm
SCHEMA ?= ./schema/openapi.yaml

export NO_UPDATE_NOTIFIER := 1

.ONESHELL:

.PHONY: ogen-deps ogen-run oapi-codegen-deps oapi-codegen-run spectral-deps spectral-run vacuum-deps vacuum-run ogen oapi-codegen spectral vacuum vacuum-dashboard check

ogen-deps:
	@if ! command -v go &> /dev/null; then
		@echo "Go is not installed. Please install Go first."
		exit 1
	fi
	@echo "Installing ogen dependencies..."
	go get -tool github.com/ogen-go/ogen/cmd/ogen@latest

ogen-run:
	@echo "Running ogen..."
	go tool ogen --target internal/ogen/api --clean $(SCHEMA) -v
	go mod tidy

ogen: ogen-deps ogen-run

oapi-codegen-deps:
	@echo "Installing oapi-codegen dependencies..."
	go get -tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest

oapi-codegen-run:
	@echo "Running oapi-codegen..."
	mkdir -p internal/codegen/api
	go tool oapi-codegen --config ./oapi-codegen.yaml $(SCHEMA)
	go mod tidy

oapi-codegen: oapi-codegen-deps oapi-codegen-run

spectral-deps:
	@if [ ! -s "$(NVM_DIR)/nvm.sh" ]; then
		@echo "Installing spectral dependencies..."
		curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.7/install.sh | bash
	fi
	source "$(NVM_DIR)/nvm.sh"
	@if ! command -v node &> /dev/null; then
		@echo "Node.js is not installed. Installing and using Node.js via nvm..."
		nvm install
		nvm use
		npm install -g npm
		npm install --save-dev @stoplight/spectral-cli
	fi

spectral-run:
	@echo "Running spectral..."
	source "$(NVM_DIR)/nvm.sh"
	nvm use
	npx spectral lint $(SCHEMA) --ruleset ./schema/spectral.yaml --verbose

spectral: spectral-deps spectral-run

vacuum-deps:
	@if ! command -v vacuum &> /dev/null; then
		@echo "Running vacuum dependencies..."
		curl -fsSL https://quobix.com/scripts/install_vacuum.sh | sudo sh
	fi

vacuum-run:
	@echo "Running vacuum..."
	vacuum upgrade
	vacuum lint $(SCHEMA)

vacuum-dashboard:
	@echo "Running vacuum dashboard..."
	vacuum dashboard $(SCHEMA)

vacuum: vacuum-deps vacuum-run

check: spectral vacuum
