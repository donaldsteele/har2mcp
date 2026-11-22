# Recording a session

`har2mcp record` opens a browser at your device's web page and records what
the page sends and receives while you use it. You name each step as you go.
The step names become tool names, so a careful recording gives you a better
server.

```sh
har2mcp record http://192.168.1.10 -o nas.har
```

## What you need

Google Chrome, Microsoft Edge or Chromium. har2mcp looks in the usual install
locations for your operating system and on your `PATH`. To use a particular
browser, pass its executable:

```sh
har2mcp record http://192.168.1.10 -o nas.har --browser "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
```

## The browser window

The window har2mcp opens is not your normal browser. It uses a new, empty
profile in a temporary folder: no extensions, no saved passwords, no cookies,
no history. The folder is deleted when recording ends. Your own browser
profile is never read or changed.

Because the profile starts empty, you always log in from scratch. That is
what lets har2mcp see how the login works.

If the device uses HTTPS with a self-signed certificate, which is common on
home networks, add `--insecure`:

```sh
har2mcp record https://192.168.1.10:5443 -o nas.har --insecure
```

## The har2mcp box

A small box sits in the bottom-right corner of every page. It stays there
when the page reloads or moves to another page.

```
┌─ har2mcp ─────────────────┐
│ Step: [ list disks      ] │
│ ● Recording      [ Done ] │
│ 12 requests this step     │
└───────────────────────────┘
```

For each action:

1. Type a name for the step, such as `list disks`, and press **Start**.
2. Do the action in the device's page: click the button, fill in the form.
3. Press **Done**.

Pressing Enter in the name field works like the button. If the box covers
something on the page, the **–** button folds it into a small har2mcp pill;
click the pill to bring it back.

The counter shows how many requests the page made during the step. If it
stays at 0, the action didn't talk to the device (the page may have used
data it already had), so try a refresh button or open the page again during
the step.

## Naming steps

A step name becomes a tool name in snake_case: `list disks` becomes
`list_disks`, `Add Share` becomes `add_share`. It also starts the tool's
description. Some tips:

- **Use a verb and a noun:** `list disks`, `add share`, `delete user`,
  `get ups status`, `set fan speed`.
- **One action per step.** If a step makes several API calls, each becomes
  its own tool. The main one (the first that changes something, or else the
  first one you clicked) gets the plain step name, and the others get the
  name plus a suffix, such as `list_disks_smart_info`.
- **Make `login` your first step.** The recorder keeps the login form's
  details: the username and password you typed, and CSS selectors for the
  two fields and the submit button. Analysis needs them to work out how the
  login works. They stay in the recording and never go into the spec.
- **Names can be anything.** Emoji and punctuation are dropped, accented
  letters lose their accents, a name that starts with a digit gets an `x_`
  prefix, a Go keyword such as `type` gets `_op` added, and duplicates get
  `_2`, `_3` and so on. You can rename any tool in the spec later.

## Getting good inputs

A tool's inputs are the values Claude fills in, like the name of a new
share. Analysis decides which values are inputs and which are fixed:

- **Values you typed become inputs**, named after the form field. Typing a
  share name into a text box is better than picking one from a list.
- **Values that differ between samples become inputs.** Do the action twice
  with different values (add two shares with different names) and the
  difference shows up.
- **Values that stay the same are fixed** in the request.
- **With only one sample,** a value that doesn't match anything you typed
  stays fixed, and the tool is marked `review: true` with a note naming the
  field. Check those in the spec, or record the step again with a different
  value.
- **Session and CSRF tokens are never inputs.** The generated server handles
  them.

## Background traffic

Many web UIs poll the device every few seconds for status. Those requests
are recorded too, with no step name. An operation that happens outside any
step, or in several steps without you clicking anything, counts as
background. It still becomes a tool, named from the API itself, for example
`getsysinfo` from an `act=getsysinfo` request.

## Things that really happen

Every step runs on the real device. If you record `reboot`, the device
reboots. If you record `delete share`, the share is gone. Only record
destructive steps you want as tools, and use something you can spare, like a
share you made for the purpose.

## Files

- **Uploads:** upload a small file. The recording keeps the form's structure
  (field names, file name, content type) and the request's total size, but
  not the file's bytes: Chrome leaves them out of what it reports. For a
  chunked upload, upload a file big enough to take several chunks; analysis
  works out the chunk size from the offsets, the upload protocol's fields or
  the request sizes.
- **Downloads:** the recording keeps the headers, size and content type, and
  the body up to the cap.
- The cap is 2 MiB (2097152 bytes) per request or response body. Change it
  with `--body-cap n`. A bigger body is left out and marked `_truncated`; its
  headers, size and content type are still recorded.

## Finishing

Close the browser window, or press Ctrl+C in the terminal. har2mcp waits a
moment for responses still on their way, then writes the file. Without
`-o`, the file is named after the host and the time, for example
`192.168.1.10-20261122-153000.har`.

## What's in the file

The output is a standard HAR 1.2 file, so other HAR viewers open it. har2mcp
adds fields whose names start with `_`, which the HAR format allows:

- `_har2mcp` at the top: the har2mcp version, the start page, your steps
  with their start and end times and the values typed in each, and the login
  form details;
- `_step` on each request made during a step: the step name;
- `_trigger` on a request that followed a click: the text, aria-label and
  role of what you clicked.

WebSocket messages are recorded too, but v0.1 doesn't turn them into tools.

## Keep it private

A recording contains the password you typed and your session cookies. On
macOS and Linux it is written with mode 0600, so only your user can read it,
and har2mcp prints a warning. Don't commit recordings to git or attach them
to issues.

To share one, for example in a bug report, make a redacted copy, or print a
summary:

```sh
har2mcp redact nas.har -o nas-redacted.har
har2mcp inspect nas.har
```

`redact` replaces passwords, cookies, auth headers and tokens with
`REDACTED`. Look through the copy before you share it.

## Using a HAR from developer tools

`analyze` also accepts a HAR you exported yourself (in Chrome: DevTools >
Network > Export HAR). This gives weaker results:

- There are no step names, so tools are named from the API, for example
  `getdisklist` instead of `list_disks`.
- The login is usually missing, because DevTools was opened after logging
  in.
- Recent versions of Chrome leave cookies and auth headers out of exports.

Analysis still writes a spec, with `auth.review: true` to show that the
login needs checking. Recording with `har2mcp record` gives better results.

## Several recordings

`analyze` takes any number of files, and analyzing into an existing spec
merges the results. A good pattern is a first recording with the common
actions, and later ones for anything you missed:

```sh
har2mcp analyze nas.har nas-2.har --name nas
```

More samples of the same action give better inputs and schemas.

## What doesn't record well

- logins that need a fresh MFA or 2FA code each time;
- "Sign in with Google" and other single sign-on redirects;
- sites with bot protection, such as Cloudflare challenges and CAPTCHAs;
- sites that sign each request with secret JavaScript;
- pages that get all their data over WebSockets;
- server-rendered HTML, where actions load new HTML pages instead of
  calling a JSON or XML API.
