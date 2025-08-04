# Lint the source code
lint:
	@golangci-lint run
.PHONY: lint

# Vulnerability checking
vulncheck:
	@govulncheck ./...
.PHONY: vulncheck

# Release a new version
release:
	@goreleaser --clean
.PHONY: release
