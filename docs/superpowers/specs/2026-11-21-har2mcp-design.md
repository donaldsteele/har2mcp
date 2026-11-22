# har2mcp: design

Date: 2026-11-21
Status: draft, awaiting approval

## Intent

Many self-hosted devices and web services have a web UI but no official API and no MCP server. The first target is a TerraMaster NAS running TOS. Under the hood, the web UI is a browser calling the device's own internal HTTP API. If we record that traffic while a person uses the UI, we can learn enough to generate an MCP server that gives Claude full control of the service.

`har2mcp` is a cross-platform command-line tool that does three things:

1. **Records** a labeled browser session.
2. **Analyzes** the recording into an editable spec.
3. **Generates** the source code for an MCP server from that spec.

The tool is meant to work with any service. TOS is the first target and the acceptance test. It's a public open-source project at `github.com/donaldsteele/har2mcp` under Apache-2.0, so docs, releases and error messages matter. Marketing focuses on building MCP servers for your own IoT and home-network devices.

## Goals

- One binary each for Windows, macOS and Linux.
- Record a browser session where the user labels each step ("list disks"), with the login captured from scratch.
- Also accept a plain HAR exported from DevTools. It has no labels and gives weaker results.
- Produce a human-editable spec file as the middle step. Rerunning analysis merges into the spec and keeps the user's hand edits.
- Generate MCP server source in Go that compiles without any manual edits.
- **Full control.** Every recorded operation becomes a tool and is switched on by default, including operations that change or destroy things.
- **Files.** Upload and download work in v1.
- Work fully offline by default. Sending anything to Claude is opt-in, through a separate `enhance` command.

## Non-goals (v1)

- Rust and C# output. These are planned. The split between spec and generator should mean adding them is mostly a matter of writing new templates.
- Discovering API calls the user never triggered, for example by scanning the web UI's JavaScript bundle.
- A proxy for capturing traffic from non-browser clients such as phone apps.
- Turning WebSocket or server-sent-event traffic into tools. This traffic is recorded but not used.
- Server-rendered HTML sites, where data comes back as HTML pages rather than JSON/XML. v1 drops HTML documents during analysis.
- Logins that need a fresh MFA/2FA code each time.
- HTTP/remote MCP transport. Generated servers use stdio only.
- Hosting or running generated servers for the user.

## Anti-goals (failure even if it "works")

- A spec or generated server that contains recorded secrets: passwords, session cookies or tokens.
- Anything leaving the machine without the user explicitly running `enhance`.
- The recorder touching the user's real browser profile.
- Generated code that doesn't compile, or needs hand edits before it builds.
- File contents passing through MCP messages. Large files must never flow through Claude.
- Rerunning `analyze` and wiping out the user's hand edits to the spec.

## What it will and won't work on

The approach suits a site whose UI is a JavaScript app talking to a JSON or XML API over HTTP. That covers NAS boxes, routers, home-automation hubs, admin panels and most self-hosted apps. GraphQL also fits, since it's one endpoint with an operation name, which the RPC split handles.

It works poorly or not at all on:

- Sites with bot protection (Cloudflare challenges, CAPTCHAs).
- Sites that sign each request with secret JavaScript, which is common on large consumer sites.
- Logins that need MFA every time.
- Single sign-on redirect chains, such as "Sign in with Google".
- Apps that only use WebSockets.
- Server-rendered HTML.

Many large consumer sites also forbid automated access in their terms, so using it there can get an account banned. For your own devices this isn't a concern.

## Constraints

- Written in Go. Go is also the v1 output language.
- Recording needs Chrome, Edge or Chromium installed.
- Recordings are HAR 1.2. Any extra data lives only in `_`-prefixed fields, which the HAR spec allows, so other HAR viewers still open the files.
- Generated servers use the official Go MCP SDK (`github.com/modelcontextprotocol/go-sdk`) over stdio.
- Generated servers read the service URL and credentials from environment variables at runtime.
- Devices on a home network often use self-signed TLS certificates. Both the recorder and the generated servers must cope with that.

## Approaches considered

### How traffic is captured

1. **DevTools HAR export only.** Nothing to install. But it usually misses the login, because people open DevTools after logging in. Recent Chrome versions strip cookies and auth headers from exports by default, and nothing records what the user meant by each request. *Kept as a fallback input.*
2. **Browser extension.** It could label steps in the user's everyday browser. But it's a separate JavaScript project, needs publishing to the Chrome and Firefox stores, and Manifest V3 extensions can't read response bodies without the `debugger` permission.
3. **Local MITM proxy.** It also captures non-browser apps. But it needs a root CA installed on each machine and has no step labels.
4. **Chosen: the tool drives Chrome over the DevTools Protocol.** A fresh profile means the login is always captured. The tool gets full bodies and cookies, can show an on-page overlay for step labels, and it all stays one binary.

### How traffic becomes tools

1. **Purely mechanical.** Works offline and gives the same output every time, but names and descriptions are rough.
2. **Claude-driven.** The best names and descriptions, but it needs an API key and sends traffic off the machine.
3. **Chosen: mechanical analysis into an editable spec, with an optional `enhance` pass by Claude.** Step labels from the recorder make the mechanical names usable on their own.

### Implementation language

- **Go (chosen).** chromedp is a mature library for controlling Chrome, cross-compiling is trivial, and `text/template` suits code generation.
- **Rust.** Its Chrome-control libraries are less mature, cross-compiling for macOS is harder, and it's slower to write for a tool that mostly moves text around.
- **C#.** It would use PuppeteerSharp or Playwright (which ships a Node driver), and the binaries are bigger.

Go is also the first output target, so tests can generate a server and compile it with the same toolchain.

### Actions that change things

1. **Chosen: expose everything, all switched on.** The user wants full control.
2. Read-only by default, with change tools switched on one by one.
3. Never expose changes.

The spec keeps an `enabled` switch on each tool (default `true`). Tools also carry MCP read/destructive annotations. These are information for the client only and don't block anything.

## Design

### CLI

```
har2mcp record   <url> [-o session.har] [--browser <path>] [--insecure]
har2mcp analyze  <file.har>... [-o service.spec.yaml]     # merges into an existing spec
har2mcp enhance  <service.spec.yaml> [--dry-run]          # optional; needs ANTHROPIC_API_KEY
har2mcp generate <service.spec.yaml> --target go [-o <dir>]
```

### `record`

- Finds an installed Chrome, Edge or Chromium. `--browser` overrides the choice.
- Launches a visible window with a fresh temporary user-data directory, which is deleted on exit. `--insecure` allows self-signed certificates.
- Captures through the DevTools Protocol `Network` domain:
  - requests and responses, including bodies
  - cookies, redirects and timings
  - WebSocket frames, which are recorded but not used in v1
- Injects an overlay into every page with a step-name field, a Done button and a per-step request count. It survives navigation, for example by registering the script to run on every new document. It reports back to the tool through a DevTools binding.

  ```
  ┌─ har2mcp ─────────────────┐
  │ Step: [ list disks      ] │
  │ ● Recording      [ Done ] │
  │ 12 requests this step     │
  └───────────────────────────┘
  ```

- For each step, it records:
  - the element clicked (text, aria-label, role)
  - the form values typed, with each field's label or name and a CSS selector
- It records the login form specifically: the username and password values and selectors for the username field, password field and submit button. Analysis needs the values to decide whether the password is sent as typed. The selectors let generated servers log in through a browser when they have to.
- Requests made outside any step are still recorded, just without a label.
- Large or binary bodies, such as file downloads and uploads, are capped:
  - Downloads keep their headers, size and content type, plus the body up to a cap.
  - Uploads keep the multipart structure (field names, filename, content type), and the bytes up to a cap.

  The caps are the builder's call.
- Output is HAR 1.2 with these extra fields:
  - `_har2mcp` at the top level: tool version, the step list with start and end times, typed inputs, and the login form details
  - `_step` and `_trigger` on each entry
- The recording contains secrets. It's written with owner-only permissions (0600), and the tool prints a warning saying so.

### `analyze`

Takes one or more HARs, recorded or plain, and builds or updates a spec.

1. **Filter.** Keep requests to the recorded site's host or hosts (configurable). Drop static resources (images, fonts, CSS, JS, HTML documents). Keep XHR and fetch calls with JSON, XML, form, text or binary-download bodies.
2. **Find the auth.**
   - **The login request.** In a recording, this is the request carrying the typed username and password, or the first one that sets a session cookie. In a plain HAR, use heuristics: a path containing login or auth, a password-like field, a response that sets cookies.
   - **How the password is sent.**
     - `http` mode: the typed password appears as typed in the request, raw or URL/form-encoded, so the server replays the login over HTTP.
     - `browser` mode: the typed password doesn't appear because it was scrambled in the page, so the generated server logs in through headless Chrome.
     - Plain HARs have no typed values to compare against, so the result is flagged for review.
   - **How the session works.** Cookies, header tokens (`Authorization` or a custom header whose value came from the login response) and CSRF tokens (a value read from a response, cookie or page and echoed back in requests). The spec records where each value comes from and where it goes.
   - **When to log in again.** On 401/403, or on a "not logged in" response body if one was seen.
3. **Group into operations.** Key each operation on method plus normalized path. Path segments that look like IDs (numbers, UUIDs, hashes) or that vary between calls become path parameters.

   **RPC split:** sometimes one endpoint gets requests where a body or query field takes several distinct values, such as `act`, `action`, `method`, `api`, `cmd`, `func` or GraphQL `operationName`. In that case, split the endpoint into one operation per value. That field is the discriminator.
4. **Work out the parameters.**
   - Values that vary between samples become inputs.
   - Constant values are fixed in the request.
   - Values matching something the user typed become inputs named after the form field.
   - Values matching a session or CSRF token are handled by the server and hidden from Claude.
   - Types are inferred from the values and the JSON structure.
   - When an operation has only one sample, values not traceable to typed input stay fixed but are marked `review: true`.
5. **Responses.** Infer a JSON schema from the samples and keep one redacted example.
6. **Classify each operation** as `read`, `change` or `destructive`.
   - GET/HEAD, or action names like get, list, query or status, count as reads.
   - Everything else counts as a change.
   - Words like delete, remove, reboot, format or wipe in the step label or action name mark it destructive.

   This feeds the MCP annotations only. It never switches a tool off.
7. **Files.**
   - `multipart/form-data` requests with file parts become upload operations.
   - Responses with `Content-Disposition: attachment` or a binary content type become download operations.
   - Chunked or resumable uploads (several requests carrying offset or chunk parameters) should be detected and modeled. If a pattern isn't understood, it's flagged rather than guessed.
8. **Naming.** Name each tool from its step label in snake_case, plus the discriminator or path when a step holds several operations. For example, `list_disks` and `list_disks_smart_info`. Duplicate names are made unique. Descriptions are built from the step label, the clicked element's text and the endpoint.
9. **Merge.** When the output spec already exists, match operations on a stable key: method, normalized path and discriminator value.
   - Samples and schemas are refreshed.
   - Fields the user edited by hand (name, description, enabled, input overrides) are kept.
   - New operations are added. Operations missing from the new recording are kept, not deleted.

   How hand edits are detected is the builder's call. The requirement is that they survive.

### The spec file

YAML, readable and editable by hand. The sketch below shows the shape only. The exact schema is the builder's call.

```yaml
har2mcp: 1
service:
  name: tos
  url_env: TOS_URL
  insecure_tls_env: TOS_INSECURE
auth:
  mode: http                 # http | browser
  login:
    request: { method: POST, path: /login, body: { user: "{{username}}", pwd: "{{password}}" } }
    form: { username: "#username", password: "#password", submit: "button[type=submit]" }
    username_env: TOS_USER
    password_env: TOS_PASSWORD
  session:
    cookies: [PHPSESSID]
    csrf: { from: { response_json: "data.token" }, to: { header: X-Csrf-Token } }
  relogin_on: [401, 403]
tools:
  - name: list_disks
    description: List all disks with model, size and health.
    enabled: true
    kind: read               # read | change | destructive
    request:
      method: POST
      path: /module/api.php
      fixed: { act: getdisklist }
    inputs: []
    response_schema: { ... }
    source: { step: "list disks", samples: 3 }
  - name: upload_file
    enabled: true
    kind: change
    file: { direction: upload, part: file }
    inputs:
      - { name: local_path, type: string, file_source: true }
      - { name: dest_folder, type: string, maps_to: body.path }
```

### `enhance` (optional)

- Reads the spec. Sends Claude the tool list: names, request shapes, step labels, clicked-element text, and examples that are redacted and truncated. It asks for better tool names, tool descriptions and input descriptions.
- Writes back **only** those text fields. It never changes request mappings.
- Never sends the raw HAR, credentials or tokens. A redaction pass runs before sending, and `--dry-run` prints exactly what would be sent.
- Uses the Claude API through the official Go SDK (`github.com/anthropics/anthropic-sdk-go`). The model can be changed and defaults to the current most capable model, `claude-opus-5-5` as of this writing.

### `generate` (Go target)

- **Output.** A Go module with `go.mod`, `main.go`, the tool files, an HTTP/session client, and a README. The README covers environment variables and how to register the server with Claude Code (`claude mcp add ...`) and Claude Desktop.
- **MCP.** Uses the official Go MCP SDK over stdio.
  - One MCP tool per enabled spec tool.
  - Input JSON schemas come from the spec inputs.
  - `readOnlyHint` and `destructiveHint` annotations come from `kind`.
- **HTTP client.**
  - cookie jar
  - logs in lazily on the first call and again on the configured triggers
  - injects CSRF and header tokens
  - can skip TLS verification when `*_INSECURE` is set
- **Browser login mode.** Uses chromedp in headless Chrome to fill the recorded login form, then copies the cookies into the HTTP client. Chrome must be installed where the server runs, and the README says so.
- **Files.** Paths refer to the machine running the server.
  - Upload tools stream a local file as multipart without loading it all into memory.
  - Download tools stream to a local path.
  - Both return metadata (path, bytes, content type), never file contents.
- **Tool results.** The response body goes back to Claude as text, truncated with a note above a size cap. The cap is the builder's call.
- **Quality bar.** The output is gofmt'd, passes `go vet` and builds with no edits. Dependencies are limited to the stdlib, the MCP SDK, and chromedp (only in browser login mode).

### Security

- **Recordings:** written 0600, with a warning, and documented as sensitive.
- **Specs:** never contain secrets. Analysis redacts passwords and tokens from examples.
- **Generated code:** never contains secrets.
- **`enhance`:** redacts before sending and supports a dry run.
- **The recorder:** always uses a throwaway browser profile.

### Testing

- **Unit tests for each analysis stage**, against synthetic fixture HARs:
  - a REST-style service
  - an RPC-style service (one endpoint plus an action field)
  - CSRF tokens
  - a scrambled password (browser mode)
  - multipart upload
  - chunked upload
  - attachment download
  - merging with hand edits
- **A fake service** written as a Go test server. It's RPC-style like a NAS, with login, CSRF and file upload/download.
- **An end-to-end test** that runs in CI on Linux, macOS and Windows:
  1. Drive `record` headlessly against the fake service with scripted clicks and step labels.
  2. Run `analyze`, then `generate`.
  3. Run `go build` on the output.
  4. Start the generated server.
  5. Call its tools with the MCP SDK's client, including an upload and a download, and check the fake service's state.

### Success

- The end-to-end test passes on all three OSes.
- On the user's TOS NAS: record a session, generate and build the server, register it with Claude Code. Claude can then list disks, create and delete a share, and upload and download a file.

### Distribution

Cross-compiled binaries for:

- windows/amd64
- darwin/arm64 and darwin/amd64
- linux/amd64 and linux/arm64

The release tooling is the builder's call.

## Risks

- **TOS details are unknown.** We don't know yet whether TOS scrambles the password, how it uploads files (chunked or not), whether it relies on WebSockets for anything that matters, or how its sessions expire. The first milestone should include recording a real TOS session and checking the analysis against it, before the generator gets much investment.
- **Heuristics will misfire on some services.** The spec file and the `review` flags are the safety valve. Error messages should point the user to the spec.

## Decisions made after the builder review

These were settled without the user. They asked for an unattended build. Each one is marked as Claude's call.

1. **No real TOS device during the build (Claude's call).**
   - The build is verified against `fakenas`, a simulated TOS-style NAS kept in the repo for tests. It has:
     - an RPC-style endpoint with an `act` field
     - login with a CSRF token returned in the login response
     - a variant where the password is scrambled in the browser
     - multipart upload and attachment download
   - Real-TOS acceptance is a manual step for the user after release.
   - To support that step, `har2mcp inspect <file.har|spec.yaml>` prints a redacted summary: detected auth mode, operations, `review` flags and files. The user can read or share it without exposing secrets.
   - `har2mcp redact <in.har> -o <out.har>` writes a HAR with secrets removed, for bug reports.
2. **When TOS needs something the design rules out, the non-goals win in v1 (Claude's call).** The escape hatch is hand-written code:
   - `generate` never overwrites a `custom.go` in the output directory.
   - The generated server calls an optional hook from that file, so users can add or override tools in Go.
   - No TOS-specific code goes in har2mcp.
3. **File tools are confined to one directory (Claude's call).** "Full control" means control of the service, not of the local disk.
   - Upload and download paths resolve inside `<SVC>_FILES_DIR`.
   - The default is `~/har2mcp-files/<service>`, created on demand.
   - Paths that escape it are rejected, including through `..` or symlinks.
4. **Public release, confirmed by the user.**
   - Module path: `github.com/donaldsteele/har2mcp`.
   - License: Apache-2.0, with a `NOTICE` file.
   - CI: GitHub Actions on Linux, macOS and Windows.
   - Releases: zips plus `SHA256SUMS` for windows/amd64, windows/arm64, darwin/amd64, darwin/arm64, linux/amd64 and linux/arm64, built from a `v*` tag.
   - Code signing and notarization are out of scope, documented in `HOW-TO-OPEN.txt` the same way as the author's other projects (bubbles, netdiag, rocket).
   - The project site lives in `site/`, is deployed to GitHub Pages, and is styled as a sibling of those projects.
   - First release: `v0.1.0`.

## Left to the builder

- The exact spec schema, and how merge detects hand edits.
- Heuristic thresholds and keyword lists.
- Overlay styling.
- Body size caps.
- Go package layout.
- The CLI framework.
- Release tooling.
- The result truncation cap.
