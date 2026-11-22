# Troubleshooting

When something goes wrong, `har2mcp inspect` is the first thing to run. It
prints a summary of a recording or a spec with secrets left out: the login
mode, the tools, and anything flagged for review.

```sh
har2mcp inspect nas.har
har2mcp inspect nas.spec.yaml
```

Its output is also the most useful thing to paste into an issue.

## Installing and starting

**Windows says "Windows protected your PC".** The binary isn't code-signed.
Click **More info**, then **Run anyway**, or unblock the zip before
extracting it. See `HOW-TO-OPEN.txt`.

**macOS says the developer cannot be verified.** Run
`xattr -d com.apple.quarantine har2mcp` in the folder, or allow it under
System Settings > Privacy & Security. See `HOW-TO-OPEN.txt`.

**Double-clicking har2mcp does nothing.** It's a command-line program. Run
it from PowerShell, Command Prompt or Terminal.

## Recording

**record can't find a browser.** Install Google Chrome, Microsoft Edge or
Chromium, or point har2mcp at one with `--browser path`.

**The page shows a certificate warning.** The device uses a self-signed
certificate. Start again with `--insecure`.

**The har2mcp box isn't on the page.** It's added to each page as it loads.
Reload the page.

**The request counter stays at 0 during a step.** The page didn't talk to
the device; it may have reused data it already had. Use the page's refresh
button, or navigate to the page again, during the step.

**I pressed Done too early.** Start another step with the same name and do
the action again.

**The login needs a code from an app or a text message.** Logins that need a
fresh code every time aren't supported in v0.1. If the device lets you
create an account without 2FA for automation, record with that account.

**The site shows a CAPTCHA or "checking your browser".** Bot protection
blocks automated browsers, and har2mcp can't work around it.

## Analyzing

**The service is called `device`.** You recorded against an IP address.
Pass `--name`, for example `--name nas`.

**Few or no tools.** Some possible causes:

- The API lives on another host or port than the page. Add it with
  `--host`, once per host.
- The device's pages are server-rendered HTML rather than a JavaScript app
  calling an API. v0.1 drops HTML documents.
- The actions happened over WebSockets, which v0.1 records but doesn't turn
  into tools.

**Tools are named like `getdisklist` instead of `list_disks`.** The
operation happened outside any step, or in several steps with no click, so
analysis treated it as background traffic and named it from the API. Rename
it in the spec, or record it again inside its own step.

**A value I want to change is fixed in the request.** The operation had
one sample and the value didn't match anything you typed. Record the step
again with a different value and analyze both recordings, or edit the spec:
move the value from `request.body` to an input (see
[spec-format.md](spec-format.md#editing-a-spec)).

**A tool says `review: true`.** Analysis guessed something. The
`review_notes` say what. Check it and fix the spec if needed. Analysis sets
the flag again each time it runs, so it can stay after you've checked.

**`auth.review: true` after analyzing a DevTools HAR.** HAR files exported
from browser developer tools usually lack the login, cookies and auth
headers. Analysis writes its best guess and asks you to check. Recording with
`har2mcp record` gives a complete picture.

**The spec won't load after my edits.** The error lists every problem with
the field it's about, such as
`tools[2] "add share": name must be lower case letters, digits and _ ...`.
Unknown keys are reported too, so check for typos.

**My edits were lost.** Merging keeps hand edits to `name`, `description`,
`enabled`, `kind` and `inputs`, and to the `auth` block. Changes to
`request`, `response`, `source` and `file` are replaced by the new analysis.
Put request changes you need to keep in `custom.go` instead.

**A tool I deleted came back.** Analyzing again adds every operation found
in the recordings. Set `enabled: false` to keep a tool out of the server.

## enhance

**enhance says ANTHROPIC_API_KEY is missing.** Set it to your Anthropic API
key. `--dry-run` works without one and prints exactly what would be sent.

**enhance rejected Claude's answer.** It refuses names that are invalid or
already taken and leaves the spec unchanged. Run it again, or edit the names
by hand.

## Generating and building

**generate says to run `go mod tidy`.** Either `go` isn't on your `PATH`, or
you passed `--no-tidy`. Install Go 1.26 or later if needed, then run
`go mod tidy` in the output folder before building.

**`go mod tidy` fails to download modules.** Building the server downloads
the MCP Go SDK (and chromedp in browser mode) through the Go module proxy.
Check your internet connection or your `GOPROXY` setting.

**The build fails in custom.go.** That file is yours, and `generate` never
touches it. Fix it, or rename it and run `generate` again to get a fresh
one.

## Running the server

**Claude doesn't see the tools.** Run `claude mcp list` to check the server
connects. Check the path to the built program, and start a new Claude
session after rebuilding.

**Every call fails with 401 or 403.** Check `<P>_URL`, `<P>_USER` and
`<P>_PASSWORD`. Then look at the `auth` block in the spec: if
`auth.review` is `true`, the login may need fixing by hand. If the device
scrambles the password in the page, `auth.mode` must be `browser`.

**Certificate errors.** Set `<P>_INSECURE=1` for a device with a
self-signed certificate.

**Browser mode fails to log in.** Google Chrome or Chromium must be installed
on the computer running the server. Check the selectors in
`auth.login.form` against the device's login page, in case a firmware update
changed it.

**A file tool says the path is outside the files folder.** File tools only
use `<P>_FILES_DIR` (default `~/har2mcp-files/<name>`). Put the file there
and pass a path relative to that folder.

**A result ends with `[truncated: <N> bytes total]`.** Responses over
100000 bytes are cut so they fit in Claude's context. A tool with an input
that limits results, such as a page size, can help.

**A tool did something I didn't want.** Every recorded tool is switched on,
including destructive ones. Set `enabled: false` on it in the spec,
generate, and rebuild.

## Reporting a problem

Open an issue at
[github.com/donaldsteele/har2mcp/issues](https://github.com/donaldsteele/har2mcp/issues)
with the har2mcp version (`har2mcp version`), your operating system, and the
`har2mcp inspect` output. Never attach a recording as it is: run
`har2mcp redact nas.har -o nas-redacted.har` and check the copy first. For
security problems, follow [SECURITY.md](../SECURITY.md) instead.
