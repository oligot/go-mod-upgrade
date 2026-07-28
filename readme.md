# go-mod-upgrade

[![Build Status](https://github.com/oligot/go-mod-upgrade/actions/workflows/go.yaml/badge.svg)](https://github.com/oligot/go-mod-upgrade/actions/workflows/go.yaml) [![License](https://img.shields.io/github/license/oligot/go-mod-upgrade)](/license) [![Release](https://img.shields.io/github/v/release/oligot/go-mod-upgrade.svg)](https://github.com/oligot/go-mod-upgrade/releases/latest)

> Update outdated Go dependencies interactively

![Screenshot](screenshot.png)

Note that only patch and minor updates are supported for now.

## Why

The Go wiki has a great section on [How to Upgrade and Downgrade Dependencies](https://go.dev/wiki/Modules#how-to-upgrade-and-downgrade-dependencies). One can run the command

```bash
go list -u -f '{{if (and (not (or .Main .Indirect)) .Update)}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}' -m all 2> /dev/null
```

to view available upgrades for direct dependencies. Unfortunately, the output is not actionable, i.e. we can't easily use it to update multiple dependencies.

This tool is an attempt to make it easier to update multiple dependencies interactively. This is similar to [yarn upgrade-interactive](https://legacy.yarnpkg.com/en/docs/cli/upgrade-interactive/), but for Go.

## Install

Pre-compiled binaries for Windows, OS X and Linux are available in the [releases page](https://github.com/oligot/go-mod-upgrade/releases).

Alternatively, with the Go toolchain, you can do

```
go install github.com/oligot/go-mod-upgrade@latest
```

## Usage

In a Go project which uses modules, you can now run

```
go-mod-upgrade
```

### List available upgrades

To see what upgrades are available without any interactivity, use the `--list` flag:

```
go-mod-upgrade --list
```

This will display all available module upgrades using the same color coding as the interactive mode, making it perfect for CI/CD pipelines or when you just want to check what's available.

Both version columns highlight from the leftmost part that changes rightwards, so the scale of the step is visible at a glance. That part takes the same colour in each, since it is one change seen twice; the rest of each version recedes, further in the one being left behind. The colour says which part moved:

- red for a new major version, where nothing of the old version remains
- yellow for a new minor
- green for a new patch
- magenta for a change of prerelease

Module names are left plain, which keeps colour beside a module meaning one thing: the advisory column has its own colours, and the two should not compete.

Colour can be turned off with `--no-color`, which is also the effect of setting `NO_COLOR`.

The colours assume a dark background, since there is no dependable way to ask a terminal what its background is. On a light one, name the `light` palette, which swaps the colours that wash out on white:

```console
$ go-mod-upgrade --colors light
```

Individual roles can be recoloured, either on their own or after a palette name:

```console
$ go-mod-upgrade --colors "cve=bold+red,from=faint"
$ go-mod-upgrade --colors "light,to-minor=cyan"
```

The roles are `name`, `indirect`, `from`, `to`, `to-major`, `to-minor`, `to-micro`, `to-prerelease`, `cve`, `cve-reachable` and `required-by`. Each takes attributes joined by `+`, from the eight terminal colours plus `bold`, `faint`, `italic`, `underline` and `none`. Naming the base colours rather than exact shades lets the terminal's own theme decide how they look. Roles left unset keep the palette's own choice.

### Indirect dependencies

By default only direct dependencies are listed. Use the `--indirect` flag to also consider the indirect requirements recorded in `go.mod`:

```
go-mod-upgrade --indirect
```

Indirect modules are marked with a dimmed `(i)` after their name. Only the requirements written in `go.mod` are offered, so upgrading them changes the recorded versions without adding new entries, and there is no need to run `go mod tidy` afterwards.

### The whole module graph

`--all` goes further and offers every module in the build list, including those reached only through other modules and so absent from `go.mod`:

```
go-mod-upgrade --all
```

Each module is shown with what pulls it in, so the reach of an upgrade is visible before accepting it:

```
golang.org/x/sys   0.42.0 -> 0.47.0  github.com/cloudflare/circl +8 more
gopkg.in/yaml.v3   3.0.1  -> 3.0.2   github.com/stretchr/testify
```

Upgrading a module that `go.mod` does not record adds a requirement to it, which only `go mod tidy` removes again, so `--all` says as much when it starts.

In a workspace, `--all` gathers every member into one list rather than asking about the same upgrade once per member, and the modules named are the members that require it. Choosing a module then asks which of them to upgrade, since whether a requirement is direct differs between members.

### Sorting

`--sort` takes a comma-separated chain of keys, each breaking ties for the one before it. The default is `+cve,+direct,+delta,+name`: advisories first, then what the code imports directly, then the size of the change, with the name settling anything still equal.

```console
$ go-mod-upgrade --sort "+delta,+name"
```

A key may be signed: `-` reverses it and `+` is the default. The keys are

- `cve` leads with the advisories the code reaches, then those merely present
- `name` compares paths without case, so related paths stay together
- `major`, `minor`, `micro` and `prerelease` compare how far that part of the version moves, the largest jump first
- `delta` stands for the four version keys together
- `deps` compares how many modules depend on each one, widest impact first
- `direct` puts the modules imported directly ahead of those reached only through another

The version keys compare the size of the jump rather than merely that something changed, so `0.4 -> 0.40` sorts above `0.1.14 -> 0.1.15`. Modules below v1 are compared on the same terms as any other.

Whatever the chain, names settle anything it leaves equal, so a listing does not shuffle between runs. `deps` needs the dependency graph that `--all` gathers, and is ignored without it.

### Vulnerabilities

`--vuln` reports the advisories affecting each module's current version, so an upgrade that resolves one is visible as such:

```console
$ go-mod-upgrade --list --indirect --vuln
golang.org/x/text (i)  CVE-2026-56852  0.4.0  -> 0.40.0
golang.org/x/sys  (i)  CVE-2026-5024   0.42.0 -> 0.47.0
```

Advisories sit between the name and the versions, since they are the reason to act. Those reaching code this module actually calls are shown in bold red, and those merely present in a dependency in yellow. `--verbose` adds the Go advisory identifier, the version carrying the fix, and a link.

The colours here describe security exposure, while those on the versions describe how disruptive the upgrade is. The two are deliberately kept in separate columns, since a module can be a safe patch bump that fixes a reachable vulnerability, or a breaking change with no security implication at all.

The scan runs in this process, using the same database and analysis as `govulncheck`, and no vulnerability score is shown because the Go vulnerability database does not publish one.

The database is kept under `~/.cache/go-mod-upgrade` and reused between runs. It is revalidated against the server each time, so it is replaced when it changes and reused otherwise, and only one copy is kept. If the server cannot be reached the cached copy is used and its age reported. If the cache cannot be written the scan falls back to the published database, so it is never required.

If the scan cannot complete, most often because the packages will not load, `--vuln` reports the failure and exits non-zero rather than presenting an unscanned tree as a clean one.

### Environment variables

Each of these sets the default for the option of the same name, so a preference need not be repeated on each run:

| Variable                   | Option        |
| -------------------------- | ------------- |
| `GO_MOD_UPGRADE_VULN`      | `--vuln`      |
| `GO_MOD_UPGRADE_INDIRECT`  | `--indirect`  |
| `GO_MOD_UPGRADE_ALL`       | `--all`       |
| `GO_MOD_UPGRADE_SORT`      | `--sort`      |
| `GO_MOD_UPGRADE_WORK_SYNC` | `--work-sync` |
| `GO_MOD_UPGRADE_IGNORE`    | `--ignore`    |
| `GO_MOD_UPGRADE_HOOK`      | `--hook`      |
| `GO_MOD_UPGRADE_FORCE`     | `--force`     |
| `GO_MOD_UPGRADE_LIST`      | `--list`      |
| `GO_MOD_UPGRADE_VERBOSE`   | `--verbose`   |
| `GO_MOD_UPGRADE_NO_COLOR`  | `--no-color`  |
| `GO_MOD_UPGRADE_COLORS`    | `--colors`    |

`GO_MOD_UPGRADE_CACHE` sets where the vulnerability database is cached. It defaults to a `go-mod-upgrade` directory inside whichever directory the platform uses for caches, and any message about the cache names the path in use.

A flag given on the command line takes precedence:

```console
export GO_MOD_UPGRADE_VULN=true
export GO_MOD_UPGRADE_SORT=risk
```

### Workspaces

In a [workspace](https://go.dev/ref/mod#workspaces), every module named by a `use` directive in `go.work` is offered in turn. Paths are resolved relative to the `go.work` file, so the tool can be run from anywhere in the workspace, and a module that cannot be read is reported and skipped rather than stopping the run.

Each module is inspected on its own, so a dependency is only offered for the modules that actually require it.

After updating, `go work sync` can be run to bring the whole workspace onto the selected versions:

```
go-mod-upgrade --work-sync
```

This is off by default, because it rewrites the `go.mod` of every module in the workspace rather than only the ones that were updated.

Additional options can be specified via the CLI global options:

```
GLOBAL OPTIONS:
   --pagesize value, -p value  Number of modules to display (% of terminal when <=1.0, or absolute number of rows) (default: 0.8)
   --force, -f                 Force update all modules in non-interactive mode (default: false)
   --list, -l                  List available module upgrades without interactivity (default: false)
   --verbose, -v               Verbose mode (default: false)
   --hook value                Hook to execute for each updated module
   --ignore value, -i value    Ignore modules matching the given regular expression
   --indirect                  Also show indirect dependencies declared in go.mod (default: false)
   --all                       Show every module in the build list, not only those recorded in go.mod (default: false)
   --vuln                      Report known vulnerabilities affecting each module (default: false)
   --sort value                Sort by a comma-separated chain of cve, name, major, minor, micro, prerelease, delta, deps, direct, each optionally signed (default: "+cve,+direct,+delta,+name")
   --no-color                  Disable colour in the output (default: false)
   --colors value              Override colours as role=attributes pairs, as in "cve=bold+red,from=faint"
   --work-sync                 Run go work sync after updating, in workspace mode (default: false)
   --help, -h                  show help (default: false)
   --version                   print the version (default: false)
```

## Integration

You may also use go-mod-upgrade with these tools:

- [Dev Container Feature](https://github.com/thediveo/devcontainer-features/blob/master/src/go-mod-upgrade/README.md)
