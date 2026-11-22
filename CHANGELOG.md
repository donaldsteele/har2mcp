# Changelog

All notable changes to har2mcp are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and har2mcp uses
[semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-22

The first release: record a device's web UI, analyze it into an editable
spec, and generate a Go MCP server from it.

### Added

- `har2mcp record <url>` opens Chrome, Edge or Chromium with a fresh
  temporary profile (deleted afterwards) and records the session as HAR 1.2.
  An on-page box names each step, and the recorder keeps the button you
  clicked, the values you typed and the login form. Recordings are written
  with mode 0600 and a warning. `--insecure` accepts self-signed
  certificates, `--browser` picks the browser, and `--body-cap` limits the
  bytes kept per body (2 MiB by default).
- `har2mcp analyze <file.har>...` turns recordings, or plain HAR files
  exported from browser developer tools, into a spec:
  - finds the login and whether the password is sent as typed (`http` mode)
    or scrambled in the page (`browser` mode);
  - finds session cookies, CSRF and header tokens, and when to log in again;
  - groups requests into operations, with path parameters and one operation
    per action value on RPC-style endpoints (`act`, `action`, `method`,
    GraphQL `operationName`, and similar);
  - works out inputs from what varies and what you typed, and flags guesses
    with `review: true`;
  - infers response schemas, marks each tool `read`, `change` or
    `destructive`, and detects uploads, downloads and chunked uploads;
  - names tools after your step labels;
  - merges into an existing spec and keeps your hand edits.
- `har2mcp inspect` prints a summary of a recording or spec with secrets left
  out.
- `har2mcp redact` writes a copy of a recording without passwords, cookies
  and tokens.
- `har2mcp enhance` (optional) asks Claude for better tool names and
  descriptions. `--dry-run` prints exactly what would be sent. The default
  model is `claude-opus-5-5`.
- `har2mcp generate --target go` writes a Go MCP server using the official
  MCP Go SDK over stdio:
  - one tool per enabled spec tool, with read-only and destructive hints;
  - logs in on the first call and again on 401/403 or a "not logged in"
    response, then retries once;
  - headless Chrome login for `browser` mode;
  - streaming uploads and downloads confined to `<P>_FILES_DIR`;
  - results capped at 100000 bytes;
  - a `custom.go` hook that is never overwritten.
- Release zips for Windows, macOS and Linux on amd64 and arm64, with
  `SHA256SUMS`.
- Docs: README, recording guide, spec format, generated servers,
  troubleshooting, and the project site.

[Unreleased]: https://github.com/donaldsteele/har2mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/donaldsteele/har2mcp/releases/tag/v0.1.0
