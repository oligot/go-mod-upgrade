# go-mod-upgrade

> Update outdated Go dependencies interactively 

![Screenshot](screenshot.png)

## Why

The Go wiki has a great section on [How to Upgrade and Downgrade Dependencies](https://github.com/golang/go/wiki/Modules#how-to-upgrade-and-downgrade-dependencies).
One can run the command
```bash
go list -u -f '{{if (and (not (or .Main .Indirect)) .Update)}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}' -m all 2> /dev/null
```
to view available upgrades for direct dependencies.
Unfortunately, the output is not actionable, i.e. we can't easily use it to update multiptle dependencies.

This tool is an attempt to make it easier to update multiptle dependencies interactively.
This is similar to [yarn upgrade-interactive](https://legacy.yarnpkg.com/en/docs/cli/upgrade-interactive/), but for Go.

## Install

With the Go toolchain, you can do

```
$ go get -u github.com/oligot/go-mod-upgrade
```

## Usage

In a Go project which uses modules, you can now run
```
$ go-mod-upgrade
```
