# Lint the source code
lint:
	@golangci-lint run
.PHONY: lint

# Release a new version
release:
	@goreleaser --clean
.PHONY: release

# Update GitHub Actions
actions-up:
	@npx actions-up
.PHONY: actions-up
