# go-mod-upgrade

[![Build Status](https://travis-ci.com/oligot/go-mod-upgrade.svg?branch=master)](https://travis-ci.com/oligot/go-mod-upgrade)
[![License](https://img.shields.io/github/license/oligot/go-mod-upgrade)](/license)
[![Release](https://img.shields.io/github/v/release/oligot/go-mod-upgrade.svg)](https://github.com/oligot/go-mod-upgrade/releases/latest)

> Update outdated Go dependencies interactively 

![Screenshot](screenshot.png)

Note that only patch and minor updates are supported for now.

## Why

The Go wiki has a great section on [How to Upgrade and Downgrade Dependencies](https://github.com/golang/go/wiki/Modules#how-to-upgrade-and-downgrade-dependencies).
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
$ go get -u github.com/oligot/go-mod-upgrade
```

## Usage

In a Go project which uses modules, you can now run
```
$ go-mod-upgrade
```

Colors in module names help identify the update type:
* green for a minor update
* yellow for a patch update
* red for a prerelease update
