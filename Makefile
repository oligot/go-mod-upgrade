golangci-lint = ./bin/golangci-lint

$(golangci-lint):
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s v1.23.1

# Lint the source code
lint: $(golangci-lint)
	@echo "Running golangci-lint..."
	@go list -f '{{.Dir}}' ./... \
		| xargs $(golangci-lint) run
.PHONY: lint
