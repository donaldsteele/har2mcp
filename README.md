# har2mcp

**Website: [donaldsteele.github.io/har2mcp](https://donaldsteele.github.io/har2mcp/)** ·
[Download](https://github.com/donaldsteele/har2mcp/releases/latest) ·
[Docs](docs/)

har2mcp turns a recorded browser session with a device's web UI into an MCP
server, so Claude can control the device.

Many devices on a home network have a web admin page but no official API and
no MCP server: the NAS, the router, a camera, a smart plug, the UPS. Behind
that page, the browser calls the device's own HTTP API. har2mcp records those
calls while you use the page and label each step ("list disks", "add share").
It then turns the recording into a spec file you can edit, and writes the Go
source code of an MCP server that makes the same calls. Build that server,
register it with Claude Code or Claude Desktop, and Claude can do what you
recorded.

```
record → session.har → analyze → nas.spec.yaml → generate → nas-mcp/ (Go source) → go build
```

- **One binary** for Windows, macOS and Linux (amd64 and arm64).
- **Records the login from scratch** in a fresh, throwaway browser profile,
  with an on-page box for naming each step.
- **An editable spec in the middle.** Rename tools, rewrite descriptions or
  switch tools off. Analyzing again merges new recordings in and keeps your
  edits.
- **Generated Go code that builds as is.** It uses the official MCP Go SDK
  over stdio, logs in by itself and logs in again when the session expires.
  Uploads and downloads stream through a local folder, so file contents never
  pass through Claude.
- **Offline by default.** Nothing leaves your machine unless you run the
  optional `enhance` command, which asks Claude for better tool names and
  descriptions.
- **Free and open source**, Apache-2.0.

**Status: v0.1.0, the first release.** The first target is a TerraMaster NAS
running TOS. The test suite runs the whole pipeline (record, analyze,
generate, build, then MCP calls including an upload and a download) against
a simulated TOS-style NAS, and CI runs it on Linux, macOS and Windows. It has
not yet been checked against a real TOS device. If you try it on your
hardware, an issue with the output of `har2mcp inspect` is very welcome.

## Requirements

- **To record:** Google Chrome, Microsoft Edge or Chromium installed.
- **To build the generated server:** [Go](https://go.dev/dl/) 1.26 or later.
- **To use it:** an MCP client that runs local stdio servers, such as Claude
  Code or Claude Desktop.
- **Only for `enhance` (optional):** an Anthropic API key.

## Install

Download the zip for your system from the
[releases page](https://github.com/donaldsteele/har2mcp/releases/latest),
check it against `SHA256SUMS`, unzip it, and put `har2mcp` (or `har2mcp.exe`)
somewhere on your `PATH`.

| System                          | Download                                |
|---------------------------------|-----------------------------------------|
| Windows PC (most laptops)       | `har2mcp_<version>_windows_amd64.zip`   |
| Windows on ARM                  | `har2mcp_<version>_windows_arm64.zip`   |
| Mac with Apple chip             | `har2mcp_<version>_darwin_arm64.zip`    |
| Mac with Intel chip             | `har2mcp_<version>_darwin_amd64.zip`    |
| Linux PC                        | `har2mcp_<version>_linux_amd64.zip`     |
| Linux on ARM (Raspberry Pi 4/5) | `har2mcp_<version>_linux_arm64.zip`     |

The binaries are not code-signed. `HOW-TO-OPEN.txt` in each zip covers the
Windows SmartScreen and macOS Gatekeeper steps.

With Go installed you can also run:

```sh
go install github.com/donaldsteele/har2mcp/cmd/har2mcp@latest
```

Check it works:

```sh
har2mcp version
```

## Quick start: a TOS-style NAS

The example below uses a NAS at `http://192.168.1.10` and the service name
`nas`. Use your own device's address and any short name you like.

### 1. Record

```sh
har2mcp record http://192.168.1.10 -o nas.har
```

Add `--insecure` if the device uses HTTPS with a self-signed certificate.

A new browser window opens with an empty profile: no extensions, no saved
passwords, no history. A small **har2mcp** box sits in the bottom-right
corner of the page. For each action you want Claude to have:

1. Type a name for the step in the box, such as `list disks`, and press
   **Start**.
2. Do the action in the device's page.
3. Press **Done**.

Make `login` your first step and log in normally. Then record a step for
each thing you want as a tool, for example `list disks`, `add share`,
`delete share`, `upload file` and `download file`. When you're finished,
close the browser window.

Every step really happens on the device. Only record a delete or a reboot
if you want that tool, and do it on something you can spare, like a test
share. [docs/recording.md](docs/recording.md) has tips for getting better
tools out of a recording.

The recording contains your password and session cookies. On macOS and
Linux it is written with owner-only permissions (0600), and har2mcp prints a
warning saying so. Don't share it: use `har2mcp redact` to make a copy you
can share.

### 2. Analyze

```sh
har2mcp analyze nas.har --name nas
```

This writes `nas.spec.yaml`: the login, how the session works, and one tool
per operation. Pass `--name` when the recording was made against an IP
address, because otherwise the service is named `device`.

### 3. Check and edit the spec

```sh
har2mcp inspect nas.spec.yaml
```

`inspect` prints a summary: the login mode, each tool with its kind, method
and path, the file tools, and anything flagged for review. It never prints
secrets, so you can paste the output into an issue.

Open `nas.spec.yaml` in an editor if you want to rename a tool, improve a
description or switch a tool off (`enabled: false`). Tools marked
`review: true` are ones analysis wasn't sure about; their `review_notes` say
why. [docs/spec-format.md](docs/spec-format.md) describes every field.

Optionally, let Claude suggest better names and descriptions. Run it with
`--dry-run` first to see exactly what would be sent:

```sh
har2mcp enhance nas.spec.yaml --dry-run
har2mcp enhance nas.spec.yaml          # needs ANTHROPIC_API_KEY
```

### 4. Generate and build

```sh
har2mcp generate nas.spec.yaml --target go
cd nas-mcp
go build -o nas-mcp .
```

On Windows, build with `go build -o nas-mcp.exe .` instead.

`generate` writes a Go module to `nas-mcp/` and runs `go mod tidy` in it,
which downloads the MCP Go SDK through the Go module proxy like any Go
build. `--no-tidy` skips that step.

### 5. Connect Claude

Claude Code:

```sh
claude mcp add --transport stdio --env NAS_URL=http://192.168.1.10 --env NAS_USER=admin --env NAS_PASSWORD=your-password nas -- /path/to/nas-mcp/nas-mcp
```

Claude Desktop: add the server to `claude_desktop_config.json` and restart
Claude Desktop.

```json
{
  "mcpServers": {
    "nas": {
      "command": "/path/to/nas-mcp/nas-mcp",
      "env": {
        "NAS_URL": "http://192.168.1.10",
        "NAS_USER": "admin",
        "NAS_PASSWORD": "your-password"
      }
    }
  }
}
```

Then ask: *"List the disks on my NAS and tell me if any look unhealthy."*

Your MCP client keeps these values in its configuration file as plain text.
If the device lets you create a second account with only the rights Claude
needs, use that one.

### 6. Record more later

Record another session and analyze it with the first one. The result is
merged into the existing spec. Your renames, descriptions, `enabled`
switches and input edits are kept, new operations are added, and tools that
are missing from the new recording are kept.

```sh
har2mcp record http://192.168.1.10 -o nas-2.har
har2mcp analyze nas.har nas-2.har --name nas
har2mcp generate nas.spec.yaml --target go
```

Use the same `--name` (or `-o`) as the first time. Without it, a device
reached by IP address gets the name `device` and a new `device.spec.yaml`
instead of an update to `nas.spec.yaml`.

`generate` never overwrites `custom.go` in the output folder, which is
where you can add your own tools in Go
([docs/generated-servers.md](docs/generated-servers.md#customgo-your-own-code)).

## Environment variables of a generated server

`<P>` is the service name in upper case: `nas` gives `NAS_URL`,
`NAS_USER`, and so on.

| Variable        | Purpose |
|-----------------|---------|
| `<P>_URL`       | The device's address, for example `http://192.168.1.10`. Default: the address you recorded |
| `<P>_USER`      | Username to log in with |
| `<P>_PASSWORD`  | Password to log in with |
| `<P>_INSECURE`  | `1` skips TLS certificate verification, for self-signed certificates |
| `<P>_FILES_DIR` | The only folder that upload and download tools may use. Default: `~/har2mcp-files/<name>` |
| `<P>_BROWSER`   | Browser-mode servers only: the path to Chrome, Chromium or Edge, if the server can't find one |

## Commands

Flags can go before or after the file names. `har2mcp <command> -h` prints a
command's flags, and `har2mcp help` lists the commands. The exit code is 0 on
success, 1 on an error and 2 on a usage error.

### `har2mcp record <url> [-o file.har] [--browser path] [--insecure] [--body-cap n]`

Opens a browser window with a fresh temporary profile at `<url>` and records
the session to a HAR 1.2 file with your step labels. The profile is deleted
when recording ends. Recording ends when you close the browser window or
press Ctrl+C.

| Flag | Meaning |
|---|---|
| `-o file.har` | Output file. Default: `<hostname>-<YYYYMMDD-HHMMSS>.har` |
| `--browser path` | The Chrome, Edge or Chromium executable to use, instead of the one har2mcp finds |
| `--insecure` | Accept self-signed and otherwise invalid TLS certificates |
| `--body-cap n` | Most bytes kept of each request or response body. Default: 2097152 (2 MiB). A bigger body is left out and marked `_truncated` |

### `har2mcp analyze <file.har>... [-o service.spec.yaml] [--name n] [--host h]...`

Builds a spec from one or more recordings, or from HAR files exported from
the browser's developer tools. If the output file already exists, the new
analysis is merged into it and your hand edits are kept.

| Flag | Meaning |
|---|---|
| `-o service.spec.yaml` | Output file. Default: `<name>.spec.yaml` |
| `--name n` | Service name: lower-case letters, digits and `_`, starting with a letter, at most 32 characters. It sets the environment variable prefix. Default: the first part of the device's host name, or `device` for an IP address |
| `--host h` | A host whose requests to keep. Repeat it for more than one. Default: the host of the recorded start page, or for a plain HAR the host most API calls went to |

### `har2mcp inspect <file.har|spec.yaml> [--name n] [--host h]...`

Prints a summary of a recording or a spec, with secrets left out: the login
mode, the tools as `<kind> <name> <METHOD> <path>`, the review flags and the
file tools. For a recording, it shows what `analyze` would make of it;
`--name` and `--host` work as they do for `analyze`.

### `har2mcp redact <in.har> -o <out.har>`

Writes a copy of a recording with passwords, cookies and tokens replaced by
`REDACTED`, for bug reports. It refuses to overwrite the input file.

### `har2mcp enhance <spec.yaml> [--model m] [--dry-run]`

Optional. Sends Claude the tool list (names, kinds, methods, paths, step
labels, button text, input names and types, and a short response example)
and asks for better tool names, tool descriptions and input descriptions.
Only those text fields are written back to the spec, in place. Request
mappings are never changed. The auth block, headers and the recording itself
are never sent.

| Flag | Meaning |
|---|---|
| `--model m` | Claude model to use. Default: `claude-opus-5-5` |
| `--dry-run` | Print exactly what would be sent, and send nothing |

Needs the `ANTHROPIC_API_KEY` environment variable, except with
`--dry-run`.

### `har2mcp generate <spec.yaml> [--target go] [-o dir] [--module path] [--no-tidy]`

Writes the source code of an MCP server for the spec.

| Flag | Meaning |
|---|---|
| `--target go` | Output language. Go is the only target in v0.1 |
| `-o dir` | Output folder. Default: `<name>-mcp` |
| `--module path` | Go module path of the generated server. Default: `<name>-mcp` |
| `--no-tidy` | Don't run `go mod tidy` in the output folder |

Every enabled tool in the spec becomes one MCP tool. `generate` rewrites its
files on every run, except `custom.go`, which is created once and never
overwritten.

### `har2mcp version`

Prints `har2mcp <version>`.

## What it works on

It suits devices and self-hosted apps whose web page is a JavaScript app
talking to a JSON or XML API over HTTP: NAS boxes, routers, home-automation
hubs, admin panels and most self-hosted apps. GraphQL fits too.

It works poorly or not at all on:

- sites with bot protection (Cloudflare challenges, CAPTCHAs);
- sites that sign each request with secret JavaScript, which is common on
  large consumer sites;
- logins that need a fresh MFA or 2FA code each time;
- HTTP Digest authentication, which some older IP cameras and printers use
  (HTTP Basic auth, where the browser shows its own sign-in box, works);
- single sign-on redirect chains, such as "Sign in with Google";
- apps that only use WebSockets (WebSocket traffic is recorded but not
  turned into tools);
- server-rendered HTML pages, where data comes back as HTML rather than
  JSON or XML.

It only knows the calls you made while recording. It doesn't scan the web
app for calls you never triggered. Large consumer sites often forbid
automated access in their terms of service, so stick to devices and services
you own or run.

## Security

- **Full control is the default.** Every recorded operation becomes a tool
  and is switched on, including ones that delete or reboot. Tools carry MCP
  read-only and destructive hints, but those are information for the client
  and block nothing. Set `enabled: false` on anything Claude shouldn't do.
- **Recordings hold secrets.** They are written with mode 0600 and a
  warning. Share them only after `har2mcp redact`.
- **Specs and generated code never contain secrets.** Analysis replaces
  passwords with `{{username}}` and `{{password}}` placeholders and redacts
  tokens from examples. The generated server reads the address and login
  from environment variables when it runs.
- **Nothing leaves your machine** unless you run `enhance`, which redacts
  before sending and has `--dry-run`.
- **The recorder never touches your real browser profile.** Each recording
  uses a new temporary profile, deleted afterwards.
- **File tools are confined to one folder,** `<P>_FILES_DIR`. Paths that
  escape it, through `..`, an absolute path or a symlink, are refused.
  Uploads and downloads return the path, size and content type, never the
  file contents.
- **TLS checks stay on** unless you set `<P>_INSECURE=1`.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Docs

- [Recording a session](docs/recording.md)
- [The spec format](docs/spec-format.md)
- [Generated servers](docs/generated-servers.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md)

## Build from source

```sh
go build ./cmd/har2mcp
```

You need Go 1.26 or later. [CONTRIBUTING.md](CONTRIBUTING.md) has the checks
to run before sending a change.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

har2mcp is a sibling of [netdiag](https://donaldsteele.github.io/netdiag/),
[bubbles](https://donaldsteele.github.io/bubbles/) and
[rocket](https://donaldsteele.github.io/rocket/).
