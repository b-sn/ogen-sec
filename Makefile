SHELL := /bin/bash
NVM_DIR := $(HOME)/.nvm

export NO_UPDATE_NOTIFIER := 1

.ONESHELL:

.PHONY: ogen-deps ogen-run spectral-deps spectral-run

ogen-deps:
	@echo "Installing ogen dependencies..."
	go get -tool github.com/ogen-go/ogen/cmd/ogen@latest

ogen-run:
	@echo "Running ogen..."
	go tool ogen --target internal/api --clean ./schema/openapi.yaml -v

spectral-deps:
	@echo "Installing spectral dependencies..."
	if [ ! -s "$(NVM_DIR)/nvm.sh" ]; then
		curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.7/install.sh | bash
	fi
	source "$(NVM_DIR)/nvm.sh"
	nvm install
	nvm use
	npm install -g npm
	npm install --save-dev @stoplight/spectral-cli

spectral-run:
	@echo "Running spectral..."
	source "$(NVM_DIR)/nvm.sh"
	nvm use
	npx spectral lint ./schema/openapi.yaml --ruleset ./schema/spectral.yaml --verbose
