.PHONY: ogen-deps ogen-run spectral-deps spectral-run

ogen-deps:
	@echo "Installing ogen dependencies..."
	go get -tool github.com/ogen-go/ogen/cmd/ogen@latest

ogen-run:
	@echo "Running ogen..."
	go tool ogen --target internal/api --clean ./schema/openapi.yaml -v

spectral-deps:
	@echo "Installing spectral dependencies..."
	curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.7/install.sh | bash
	export NVM_DIR="$HOME/.nvm"
	[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
	[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"
	nvm install node && nvm use node
	npm install -g npm
	npm install -g @stoplight/spectral-cli

spectral-run:
	@echo "Running spectral..."
	spectral lint ./schema/openapi.yaml --ruleset ./schema/spectral.yaml  --verbose