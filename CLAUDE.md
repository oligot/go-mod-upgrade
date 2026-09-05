# go-mod-upgrade

## Commands

Tooling is pinned in `mise.toml`; run tasks through mise (`mise tasks`), not bare `go`/`golangci-lint`.

## Changelog

Every user-facing change (feature, breaking change, bug fix) must be added to
`CHANGELOG.md` in the same commit, under the topmost unreleased version
heading. Format: [Common Changelog](https://common-changelog.org/) — imperative
mood, one line per entry, sections ordered Changed / Added / Removed / Fixed,
breaking changes prefixed `**Breaking:**` and listed first, each entry
referencing a PR/issue or commit link.

Skip CI, dev-tooling and internal-refactor churn — the changelog is for users.

## Conventions

- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org)
  (`feat:`, `fix:`, `chore:`, `refactor:`, `docs:`, `perf:`).
- Never hand-edit the pinned action SHAs in `.github/workflows` — run `mise run pinact`.
- `go list` output is expensive to reproduce: cover parsing changes with a
  fixture in `internal/discover/testdata` rather than shelling out in tests.
