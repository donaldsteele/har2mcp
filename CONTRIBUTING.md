# Contributing to har2mcp

Thanks for helping. har2mcp is one Go binary with four stages joined by two
file formats:

```
record → HAR 1.2 (+ _har2mcp fields) → analyze → spec YAML → generate → Go module
```

Before you start, read [SECURITY.md](SECURITY.md) so you know which
guarantees matter, and the design notes in
[docs/superpowers/specs/](docs/superpowers/specs/).

## Development setup

You need:

- Go 1.27 (CI uses `1.27.x`; `go.mod` says `go 1.26`, which is the oldest Go
  that builds har2mcp and the servers it generates)
- Google Chrome, Microsoft Edge or Chromium, for the recorder and end-to-end
  tests
- Git, and `zip` (or `7z`) to build release zips

Clone the repository, then:

```sh
go build ./cmd/har2mcp
./har2mcp help
```

## Layout

| Path | What it is |
|---|---|
| `cmd/har2mcp/` | The CLI: one file per command, a dispatch table in `main.go` |
| `internal/har/` | HAR 1.2 types with the `_har2mcp` extensions, load, save, redact |
| `internal/spec/` | The spec types, load, save, validation, merge and name rules |
| `internal/record/` | The recorder: drives Chrome over the DevTools Protocol, injects the step overlay |
| `internal/analyze/` | Turns HAR files into a spec: filter, auth, grouping, parameters, schemas, kinds, files, names |
| `internal/inspect/` | The redacted summaries printed by `har2mcp inspect` |
| `internal/enhance/` | The optional Claude pass over names and descriptions |
| `internal/generate/` | The Go code generator and its templates (`gotarget/`) |
| `internal/fakenas/` | A simulated TOS-style NAS that the tests record against |
| `e2e/` | End-to-end tests: record, analyze, generate, build, then MCP calls |
| `site/` | The project website, published to GitHub Pages by `pages.yml` |
| `docs/` | User docs |

The stages only talk to each other through the `har` and `spec` types.

## Checks before you push

```sh
bash scripts/gofmt-check.sh         # must print nothing
go vet ./...
go test ./...
go test -race ./...                 # CI runs this on Linux and macOS
```

The recorder and end-to-end tests start a headless browser and build
generated servers with `go`. They skip themselves when no browser is found or
`go` is not on `PATH`, and with `go test -short ./...`.

To check that every release target still builds:

```sh
VERSION=0.0.0-dev bash scripts/build.sh
```

It writes six zips and `SHA256SUMS` to `dist/`.

CI runs gofmt, vet and the tests on Linux, macOS and Windows, the race tests
on Linux and macOS, and a cross-build of all six targets.

## Conventions

- **Pure Go.** Every build uses `CGO_ENABLED=0` and must build for
  windows/amd64, windows/arm64, darwin/amd64, darwin/arm64, linux/amd64 and
  linux/arm64.
- **Few dependencies.** har2mcp uses chromedp and cdproto, the MCP Go SDK,
  `go.yaml.in/yaml/v3` and the Anthropic Go SDK. Adding another needs a
  reason in the pull request.
- **No secrets in output.** Specs, generated code, logs, error messages and
  the `enhance` payload never contain recorded passwords, cookies or tokens.
  Add a test when you touch any of them.
- **Generated code must build as is.** It is gofmt-clean, passes `go vet`,
  and builds with `go build ./...` without edits. Its only dependencies are
  the standard library, the MCP Go SDK, and chromedp in browser login mode.
- **No device-specific code.** har2mcp stays generic. When a device needs
  something the generator can't express, the answer is a better spec field or
  the `custom.go` hook, not a special case for one product.
- **Tests are deterministic.** Use `internal/fakenas` and `httptest`, not
  real devices or the internet.
- **No placeholder markers** (TODO or FIXME) in committed code. Open an issue
  instead.
- **Docs follow the code.** If you change a command, a flag, an environment
  variable or a spec field, update [README.md](README.md), the matching file
  in `docs/`, and `site/index.html` if it shows that command.

## Submitting changes

1. Open an issue first for larger changes, so the design can be agreed.
2. Keep each pull request focused, and describe what it changes and how you
   tested it.
3. Include tests for behaviour changes.
4. When a device doesn't work, the most useful report is the output of
   `har2mcp inspect` on the recording and on the spec, which leaves secrets
   out.

By contributing you agree that your contribution is licensed under the
Apache License 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)).

## Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`: it runs the tests,
builds the six zips with `scripts/build.sh`, checks them against
`SHA256SUMS`, and publishes a GitHub release. A tag with a `-` in it (such as
`v0.2.0-rc1`) is published as a pre-release.

The site in `site/` is published by `.github/workflows/pages.yml` on every
push to `main` that changes it. On a new repository (or a fork), switch
GitHub Pages to build from GitHub Actions once, or the workflow fails with
"Get Pages site failed":

```sh
gh api -X POST repos/<owner>/har2mcp/pages -f build_type=workflow
gh workflow run pages.yml
```
