# Changelog

## [0.13.0] - Unreleased

_When upgrading: `--ignore` values are now regular expressions, so anchor a pattern with `^…$` to match a whole module path, and an invalid pattern is a hard error._

### Changed

- **Breaking:** treat `--ignore` values as regular expressions instead of plain substrings ([`9f094f7`](https://github.com/oligot/go-mod-upgrade/commit/9f094f7))

## [0.12.0] - 2025-09-21

### Changed

- Bump dependencies ([`5803b8e`](https://github.com/oligot/go-mod-upgrade/commit/5803b8e), [`f284096`](https://github.com/oligot/go-mod-upgrade/commit/f284096))

### Added

- Add `--list` flag to print available upgrades without interactivity ([`920a076`](https://github.com/oligot/go-mod-upgrade/commit/920a076))

### Fixed

- Fix update-type colors in the module listing ([`cee4244`](https://github.com/oligot/go-mod-upgrade/commit/cee4244))

## [0.11.0] - 2025-02-16

### Added

- Add support for upgrading Go 1.24 tool dependencies ([#60](https://github.com/oligot/go-mod-upgrade/pull/60))

### Fixed

- Update every module instead of stopping at the first one when `--force` is set ([`95911bd`](https://github.com/oligot/go-mod-upgrade/commit/95911bd))

## [0.10.0] - 2024-04-08

### Changed

- Update `golang.org/x/mod` ([`f6862d0`](https://github.com/oligot/go-mod-upgrade/commit/f6862d0))

### Added

- Add `--ignore` flag to skip modules by name ([#42](https://github.com/oligot/go-mod-upgrade/issues/42))

### Fixed

- Fix module discovery for a module inside a workspace ([#35](https://github.com/oligot/go-mod-upgrade/issues/35))

## [0.9.1] - 2022-08-23

### Changed

- Only download packages when updating them ([`6b3fddc`](https://github.com/oligot/go-mod-upgrade/commit/6b3fddc))

### Fixed

- Fix upgrades that were broken in 0.9.0 ([#32](https://github.com/oligot/go-mod-upgrade/issues/32))

## [0.9.0] - 2022-06-14

### Added

- Add support for Go 1.18 workspaces, honouring the `GOWORK` environment variable ([#25](https://github.com/oligot/go-mod-upgrade/issues/25))

### Fixed

- Fix workspace support when run from a subfolder ([#28](https://github.com/oligot/go-mod-upgrade/issues/28))
- Fix module discovery when `GOWORK=off` ([#29](https://github.com/oligot/go-mod-upgrade/issues/29))

## [0.8.0] - 2022-03-22

### Added

- Add a colored progress spinner while discovering modules ([#21](https://github.com/oligot/go-mod-upgrade/pull/21), [#23](https://github.com/oligot/go-mod-upgrade/issues/23))

## [0.7.0] - 2021-12-09

### Changed

- Print a meaningful version when installed with `go install` ([#19](https://github.com/oligot/go-mod-upgrade/issues/19))

## [0.6.2] - 2021-11-27

### Changed

- Update dependencies ([`d303d46`](https://github.com/oligot/go-mod-upgrade/commit/d303d46))

## [0.6.1] - 2021-04-08

### Changed

- Set the go directive to 1.15 ([`3330d70`](https://github.com/oligot/go-mod-upgrade/commit/3330d70))

### Added

- Add structured logging ([`8468540`](https://github.com/oligot/go-mod-upgrade/commit/8468540))

## [0.6.0] - 2021-03-24

### Added

- Add `--hook` flag to execute a command for each updated module ([`d6f47c7`](https://github.com/oligot/go-mod-upgrade/commit/d6f47c7))

## [0.5.0] - 2021-03-18

### Changed

- Parse command line arguments with `urfave/cli` ([`bc3c9a1`](https://github.com/oligot/go-mod-upgrade/commit/bc3c9a1))

### Added

- Add `--force` flag to update all modules non-interactively ([`31d25f9`](https://github.com/oligot/go-mod-upgrade/commit/31d25f9))

## [0.4.1] - 2021-03-12

### Changed

- Bump the `survey` package ([#9](https://github.com/oligot/go-mod-upgrade/pull/9))

### Fixed

- Fix the summary output ([#8](https://github.com/oligot/go-mod-upgrade/issues/8))

## [0.4.0] - 2021-02-12

### Changed

- Accept Go release candidate versions by no longer parsing the Go version ([#7](https://github.com/oligot/go-mod-upgrade/issues/7))
- Improve error handling for module parsing and versioning ([#7](https://github.com/oligot/go-mod-upgrade/issues/7))

### Added

- Add `--verbose` flag to print more information ([#7](https://github.com/oligot/go-mod-upgrade/issues/7))

### Removed

- **Breaking:** drop support for Go versions before 1.14 ([#7](https://github.com/oligot/go-mod-upgrade/issues/7))

## [0.3.0] - 2020-12-28

### Added

- Add `--pagesize` flag to set the number of modules shown at once ([#6](https://github.com/oligot/go-mod-upgrade/pull/6))

## [0.2.1] - 2020-08-03

### Fixed

- Print the error message of the upgrade command ([#5](https://github.com/oligot/go-mod-upgrade/pull/5))

## [0.2.0] - 2020-07-06

### Fixed

- Support Go 1.14 with vendored dependencies by passing `-mod=mod` ([#4](https://github.com/oligot/go-mod-upgrade/issues/4))

## [0.1.2] - 2020-02-03

### Changed

- Improve the documentation ([`7a46e4d`](https://github.com/oligot/go-mod-upgrade/commit/7a46e4d), [`78c9dfd`](https://github.com/oligot/go-mod-upgrade/commit/78c9dfd))

## [0.1.1] - 2020-01-31

### Added

- Build Windows binaries ([`b418829`](https://github.com/oligot/go-mod-upgrade/commit/b418829))

### Fixed

- Remove `dist` before publishing so releases contain the expected archives ([`da4b411`](https://github.com/oligot/go-mod-upgrade/commit/da4b411))

## [0.1.0] - 2020-01-31

_Initial release._

[0.13.0]: https://github.com/oligot/go-mod-upgrade/compare/v0.12.0...main
[0.12.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.12.0
[0.11.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.11.0
[0.10.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.10.0
[0.9.1]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.9.1
[0.9.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.9.0
[0.8.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.8.0
[0.7.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.7.0
[0.6.2]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.6.2
[0.6.1]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.6.1
[0.6.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.6.0
[0.5.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.5.0
[0.4.1]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.4.1
[0.4.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.4.0
[0.3.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.3.0
[0.2.1]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.2.1
[0.2.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.2.0
[0.1.2]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.1.2
[0.1.1]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.1.1
[0.1.0]: https://github.com/oligot/go-mod-upgrade/releases/tag/v0.1.0
