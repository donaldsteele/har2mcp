# Security policy

## Reporting a vulnerability

Please do not report security problems in public issues or pull requests.

Use GitHub's private vulnerability reporting: open the repository's
**Security** tab and choose **Report a vulnerability**. Include:

- the har2mcp version (`har2mcp version`) or the commit,
- your operating system and browser,
- steps to reproduce, and the impact you expect,
- whether you have shared the details anywhere else.

Do not attach recordings (`.har` files), passwords, cookies or tokens. A
recording holds the password you typed and your session cookies. If a
recording is needed to show the problem, run `har2mcp redact` on it first and
check the copy, or describe the problem with made-up data.

## What to expect

- We acknowledge the report as soon as the maintainers see it, confirm
  whether it is a vulnerability, and agree on a fix and a disclosure date with
  the reporter.
- We credit the reporter if they want credit.
- Fixes ship in a new tagged release with a note in the release notes.

## Supported versions

Security fixes go to the latest tagged release. Older releases do not receive
fixes. Pre-release tags (for example `v0.2.0-rc1`) are not supported once a
stable release exists.

A server that har2mcp generated does not update itself. After a fix in the
generator, run `har2mcp generate` again and rebuild the server.

## What har2mcp promises

These are the guarantees the code and tests are meant to keep. A way to break
one of them is a vulnerability.

- **Specs never contain recorded secrets.** Passwords, session cookies and
  tokens from a recording never appear in a spec file. The login request uses
  `{{username}}` and `{{password}}` placeholders, and examples are redacted.
- **Generated code never contains secrets.** A generated server reads the
  device address and login from environment variables when it runs.
- **Nothing leaves the machine unless you run `har2mcp enhance`.** `enhance`
  never sends the recording, the auth block, headers or credentials, and
  `enhance --dry-run` prints the exact payload and sends nothing.
- **Recordings are written with mode 0600** (owner only, on macOS and Linux)
  and a warning is printed.
- **The recorder never uses your real browser profile.** Every recording
  starts a new temporary profile and deletes it afterwards.
- **File tools in generated servers stay inside `<P>_FILES_DIR`.** A local
  path that escapes it after cleaning and resolving symlinks, through `..`, an
  absolute path or a symlink, is an error and nothing is read or written.
- **File contents never pass through MCP messages.** Upload and download
  tools return the path, size and content type only.
- **TLS verification stays on** in the recorder unless you pass `--insecure`,
  and in generated servers unless `<P>_INSECURE=1` is set.

## What it does not protect

- **Full control is the design.** A generated server exposes every recorded
  operation and switches all of them on, including ones that delete, format
  or reboot. The MCP read-only and destructive hints are information for the
  client, not a block. Review the spec and set `enabled: false` on tools you
  don't want Claude to call.
- **Credentials in your MCP client.** The device password is passed to the
  generated server as an environment variable, which MCP clients keep in
  their configuration files as plain text. Use a separate, limited account on
  the device when it supports one.
- **The device itself.** har2mcp makes the same calls as the device's web
  page. If the device's API is weak, for example plain HTTP on a shared
  network, so is the generated server.
- **Anyone who can read your recordings or your MCP configuration** has your
  device login.

## Scope

In scope: the har2mcp binary, the code it generates, and the release
workflow.

Out of scope: vulnerabilities in the devices you record, the security of the
host operating system or browser, and problems that need an attacker who can
already read your files.
