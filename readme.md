# go-mod-upgrade

[![Build Status](https://github.com/oligot/go-mod-upgrade/actions/workflows/go.yaml/badge.svg)](https://github.com/oligot/go-mod-upgrade/actions/workflows/go.yaml)
[![License](https://img.shields.io/github/license/oligot/go-mod-upgrade)](/license)
[![Release](https://img.shields.io/github/v/release/oligot/go-mod-upgrade.svg)](https://github.com/oligot/go-mod-upgrade/releases/latest)

> Update outdated Go dependencies interactively 

![Screenshot](screenshot.png)

Note that only patch and minor updates are supported for now.

## Why

The Go wiki has a great section on [How to Upgrade and Downgrade Dependencies](https://go.dev/wiki/Modules#how-to-upgrade-and-downgrade-dependencies).
One can run the command
```bash
go list -u -f '{{if (and (not (or .Main .Indirect)) .Update)}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}' -m all 2> /dev/null
```
to view available upgrades for direct dependencies.
Unfortunately, the output is not actionable, i.e. we can't easily use it to update multiple dependencies.

This tool is an attempt to make it easier to update multiple dependencies interactively.
This is similar to [yarn upgrade-interactive](https://legacy.yarnpkg.com/en/docs/cli/upgrade-interactive/), but for Go.

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

Colors in module names help identify the update type:
* yellow for a minor update
* green for a patch update
* red for a prerelease update

### Indirect dependencies

By default only direct dependencies are listed. Use the `--indirect` flag to also
consider the indirect requirements recorded in `go.mod`:
```
go-mod-upgrade --indirect
```

Indirect modules are marked with a dimmed `(i)` after their name. Only the
requirements written in `go.mod` are offered, so upgrading them changes the
recorded versions without adding new entries, and there is no need to run
`go mod tidy` afterwards.

### Sorting

Modules are listed by name, comparing case-insensitively so that related paths
stay together. Use `--sort` to order them differently:
```
go-mod-upgrade --sort risk
```

* `name` sorts alphabetically (the default)
* `risk` sorts from safest to most disruptive, leaving major version bumps last
* `deps` sorts by how many modules depend on each one, widest impact first

### Workspaces

In a [workspace](https://go.dev/ref/mod#workspaces), every module named by a
`use` directive in `go.work` is offered in turn. Paths are resolved relative to
the `go.work` file, so the tool can be run from anywhere in the workspace, and a
module that cannot be read is reported and skipped rather than stopping the run.

Each module is inspected on its own, so a dependency is only offered for the
modules that actually require it.

After updating, `go work sync` can be run to bring the whole workspace onto the
selected versions:
```
go-mod-upgrade --work-sync
```

This is off by default, because it rewrites the `go.mod` of every module in the
workspace rather than only the ones that were updated.

Additional options can be specified via the CLI global options:

``` 
GLOBAL OPTIONS:
   --pagesize value, -p value  Specify page size (default: 10)
   --force, -f                 Force update all modules in non-interactive mode (default: false)
   --list, -l                  List available module upgrades without interactivity (default: false)
   --verbose, -v               Verbose mode (default: false)
   --hook value                Hook to execute for each updated module
   --ignore value, -i value    Ignore modules matching the given regular expression
   --indirect                  Also show indirect dependencies declared in go.mod (default: false)
   --sort value                Sort modules by name, risk, deps (default: "name")
   --work-sync                 Run go work sync after updating, in workspace mode (default: false)
   --help, -h                  show help (default: false)
   --version                   print the version (default: false)
```

## Integration

You may also use go-mod-upgrade with these tools:

* [Dev Container Feature](https://github.com/thediveo/devcontainer-features/blob/master/src/go-mod-upgrade/README.md)
