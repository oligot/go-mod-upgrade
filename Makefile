# Lint the source code
lint:
	@golangci-lint run
.PHONY: lint

# Release a new version
release:
	@goreleaser --clean
.PHONY: release
