# The spec format

A spec is the YAML file between `har2mcp analyze` and `har2mcp generate`.
`analyze` writes it, you can edit it by hand, and `generate` turns it into
source code. Analyzing again merges into it and keeps your edits.

This page describes format version 1, the one har2mcp v0.1 reads and
writes.

## Example

A spec for an example NAS with four tools. The `delete_share` tool has been
switched off by hand (`enabled: false`).

```yaml
# har2mcp spec. Edit freely: rerunning 'har2mcp analyze' keeps your changes to
# tool names, descriptions, enabled, kind and inputs, and to the auth block.
# Format: https://github.com/donaldsteele/har2mcp/blob/main/docs/spec-format.md
har2mcp: 1
service:
  name: nas
  base_url: http://192.168.1.10
  hosts:
    - 192.168.1.10
auth:
  mode: http
  login:
    page_url: http://192.168.1.10/
    request:
      method: POST
      path: /login
      body_type: json
      body:
        pwd: '{{password}}'
        user: '{{username}}'
    form:
      username: '#username'
      password: '#password'
      submit: button[type=submit]
  session:
    cookies:
      - PHPSESSID
    tokens:
      - name: csrf
        from:
          response_json: data.token
        to:
          header: X-Csrf-Token
  relogin_on:
    - 401
    - 403
  relogin_body_contains: not logged in
auth_generated: 6120cd8d
tools:
  - name: list_disks
    description: List disks. Calls POST /module/api.php (act=getdisklist). Recorded from the 'Disks' control.
    enabled: true
    kind: read
    request:
      method: POST
      path: /module/api.php
      body_type: json
      body:
        act: getdisklist
      discriminator: act
    inputs: []
    response:
      content_type: application/json
      schema:
        properties:
          data:
            items:
              properties:
                health:
                  type: string
                id:
                  type: string
                model:
                  type: string
                size_gb:
                  type: integer
              type: object
            type: array
          ok:
            type: boolean
        type: object
      example:
        data:
          - health: good
            id: sda
            model: 4TB NAS HDD
            size_gb: 4000
        ok: true
    source:
      key: POST /module/api.php act=getdisklist
      steps:
        - list disks
      samples: 2
      trigger: Disks
    generated:
      description: 276729aa
      enabled: b5bea41b
      inputs: "74234e98"
      kind: 6f365882
      name: 2cacdc4d
  - name: add_share
    description: Add share. Calls POST /module/api.php (act=addshare). Recorded from the 'Create' control.
    enabled: true
    kind: change
    request:
      method: POST
      path: /module/api.php
      body_type: json
      body:
        act: addshare
      discriminator: act
    inputs:
      - name: name
        type: string
        description: Share name
        required: true
        in: body
        field: name
        example: media
    response:
      content_type: application/json
      schema:
        properties:
          ok:
            type: boolean
        type: object
      example:
        ok: true
    source:
      key: POST /module/api.php act=addshare
      steps:
        - add share
      samples: 2
      trigger: Create
    generated:
      description: 8da7d41d
      enabled: b5bea41b
      inputs: fe3d5ed2
      kind: f1d58fbb
      name: 8043ad6b
  - name: delete_share
    description: Delete share. Calls POST /module/api.php (act=delshare). Recorded from the 'Delete' control.
    enabled: false
    kind: destructive
    request:
      method: POST
      path: /module/api.php
      body_type: json
      body:
        act: delshare
      discriminator: act
    inputs:
      - name: name
        type: string
        required: true
        in: body
        field: name
        example: media
    response:
      content_type: application/json
      schema:
        properties:
          ok:
            type: boolean
        type: object
      example:
        ok: true
    source:
      key: POST /module/api.php act=delshare
      steps:
        - delete share
      samples: 1
      trigger: Delete
    generated:
      description: 6b154ba8
      enabled: b5bea41b
      inputs: e9b40258
      kind: 9059eb24
      name: 4a88f4e2
  - name: upload_file
    description: Upload file. Calls POST /module/upload.php. Recorded from the 'Upload' control.
    enabled: true
    kind: change
    request:
      method: POST
      path: /module/upload.php
      body_type: multipart
    inputs:
      - name: local_path
        type: string
        description: File to upload, relative to NAS_FILES_DIR
        required: true
        in: file
      - name: path
        type: string
        description: Destination folder on the NAS
        required: true
        in: body
        field: path
        example: /public
    file:
      direction: upload
      part: file
    response:
      content_type: application/json
      schema:
        properties:
          ok:
            type: boolean
        type: object
      example:
        ok: true
    source:
      key: POST /module/upload.php
      steps:
        - upload file
      samples: 1
      trigger: Upload
    generated:
      description: 8132df51
      enabled: b5bea41b
      inputs: 10a8b13e
      kind: f1d58fbb
      name: efe6a64b
```

## Top level

| Key | Meaning |
|---|---|
| `har2mcp` | Format version. Always `1`. A spec without this line is rejected, and so is a newer version than your har2mcp knows. |
| `service` | Which device or app this is. See [service](#service). |
| `auth` | How to log in and keep the session. See [auth](#auth). |
| `auth_generated` | A hash of the `auth` block as analysis wrote it, used to detect hand edits. Leave it alone. |
| `tools` | One entry per MCP tool. See [tools](#tools). |

Unknown keys are errors, so a typo in a hand edit is reported instead of
silently ignored. Every error names the field it is about, and all problems
are reported at once.

## service

| Key | Meaning |
|---|---|
| `name` | Required. Lower-case letters, digits and `_`, starting with a letter, at most 32 characters. |
| `base_url` | The address you recorded against. The generated server takes the address from `<P>_URL` when it runs. |
| `hosts` | The hosts whose requests analysis kept. |

`name` decides a lot:

- the environment variable prefix: `nas` gives `NAS_URL`, `NAS_USER`,
  `NAS_PASSWORD`, `NAS_INSECURE` and `NAS_FILES_DIR`;
- the server's name, `nas-mcp`, and the default output folder of `generate`;
- the default files folder, `~/har2mcp-files/nas`.

If you change it, update the environment variables in your MCP client too.

## auth

| Key | Meaning |
|---|---|
| `mode` | `none`, `http` or `browser`. See below. |
| `login` | Required unless `mode` is `none`. |
| `login.page_url` | The page with the login form. |
| `login.request` | The login request, in the same shape as a tool's [request](#request). `{{username}}` and `{{password}}` mark where the username and password go. |
| `login.form` | CSS selectors for the login form: `username`, `password` and `submit`. Required in `browser` mode. |
| `session.cookies` | Names of the cookies that carry the session. |
| `session.tokens` | Values the server copies from one place to another, such as a CSRF token. See [tokens](#tokens). |
| `relogin_on` | HTTP status codes that mean "log in again", usually `[401, 403]`. |
| `relogin_body_contains` | Text in a response body that means "log in again", such as `not logged in`. |
| `review` | `true` when analysis isn't sure about the login. |
| `review_notes` | Why, one line per problem. |

The three modes:

- **`none`:** the device needs no login.
- **`http`:** the password appeared in the login request exactly as you
  typed it (raw, or URL or form encoded). The generated server sends the
  same request with `{{username}}` and `{{password}}` filled in from
  `<P>_USER` and `<P>_PASSWORD`.
- **`browser`:** the password you typed did not appear in the login
  request, so the page scrambled it before sending (hashing it with a value
  from the server, for example). The generated server opens the login page
  in headless Chrome, fills in `login.form`, waits for the session cookie and
  copies the cookies into its HTTP client. Chrome must be installed where the
  server runs.

A plain HAR exported from developer tools has no typed values to compare
against, so analysis sets `review: true` and explains what it guessed.

The generated server logs in on its first call. When a response has a status
in `relogin_on`, or a body containing `relogin_body_contains`, it logs in
again and retries the call once.

### tokens

```yaml
tokens:
  - name: csrf
    from:
      response_json: data.token
    to:
      header: X-Csrf-Token
```

`from` says where the value is read and `to` says where it is sent on later
requests. Each sets exactly one of these keys:

| Key | Meaning |
|---|---|
| `response_json` | A dotted path into a JSON response body, such as `data.token` |
| `response_header` | A response header |
| `cookie` | A cookie |
| `header` | A request header |
| `query` | A query string key |
| `body` | A dotted path into the request body |

Tokens are handled by the server and are never tool inputs.

## tools

| Key | Meaning |
|---|---|
| `name` | The MCP tool name. Lower-case letters, digits and `_`, starting with a letter, at most 64 characters, unique in the spec. |
| `description` | What Claude reads to decide when to use the tool. Worth improving by hand or with `har2mcp enhance`. |
| `enabled` | `false` leaves the tool out of the generated server. Every tool starts as `true`. |
| `kind` | `read`, `change` or `destructive`. See below. |
| `request` | The HTTP request the tool sends. See [request](#request). |
| `inputs` | The tool's arguments. See [inputs](#inputs). |
| `file` | Only on upload and download tools. See [file](#file). |
| `response` | What the request returned while recording. See [response](#response). |
| `source` | Where the tool came from. See [source](#source). |
| `review` | `true` when analysis guessed something about this tool. |
| `review_notes` | What it guessed, one line per field. |
| `generated` | Hashes of the editable fields as analysis wrote them, used to detect hand edits. Leave them alone. |

`kind` sets the MCP hints on the tool: `read` sets `readOnlyHint`, and
`destructive` sets `destructiveHint`. Analysis counts GET and HEAD requests,
and actions named like get, list, query or status, as reads; everything else
is a change. Words like delete, remove, reboot, format or wipe in the step
name or action make it destructive. The hints are information for the MCP
client. They never block a call, and they never switch a tool off.

### request

| Key | Meaning |
|---|---|
| `method` | An upper-case HTTP method: `GET`, `POST`, `PUT`, `DELETE` ... |
| `path` | Starts with `/`. May contain `{placeholder}` segments, such as `/api/v1/disks/{id}`, each filled by an input with `in: path`. |
| `query` | Fixed query string values. |
| `body_type` | `none`, `json`, `form` or `multipart`. |
| `body` | Fixed body values. |
| `headers` | Fixed request headers. |
| `discriminator` | On an RPC-style endpoint, the body or query field that names the action, such as `act`. Its value is fixed in `body` or `query`. |

When a tool is called, its inputs are merged into the fixed `query` and
`body` values.

### inputs

```yaml
inputs:
  - name: name
    type: string
    description: Share name
    required: true
    in: body
    field: name
    example: media
```

| Key | Meaning |
|---|---|
| `name` | The argument name Claude sees. Letters, digits and `_`, starting with a letter, at most 64 characters, unique in the tool. |
| `type` | `string`, `integer`, `number`, `boolean`, `array` or `object`. |
| `description` | Shown to Claude next to the argument. |
| `required` | `true` if Claude must always pass it. |
| `in` | Where the value goes: `path`, `query`, `body` or `file`. |
| `field` | Where exactly. See below. |
| `example` | A value seen while recording. |

What `field` means depends on `in`:

- **`path`:** the `{placeholder}` in `request.path` to fill. If `field` is
  empty, the input's `name` is used. Every placeholder needs exactly one
  such input.
- **`query`:** the query string key.
- **`body`:** a dotted path into the body. `config.name` sets
  `{"config": {"name": ...}}`. In a `multipart` body it is the form field
  name.
- **`file`:** the input is a path to a local file, inside `<P>_FILES_DIR`.
  Only file tools have one, and they have exactly one. `field` can be left
  out.

### file

```yaml
file:
  direction: upload
  part: file
```

| Key | Meaning |
|---|---|
| `direction` | `upload` or `download`. |
| `part` | The multipart part that carries the file. Required for uploads. |
| `chunked` | Set when uploads are sent in pieces. See below. |

An upload tool streams a local file to the device as multipart form data. A
download tool streams the response to a local file. Both take their local
path from the tool's `in: file` input, resolved inside `<P>_FILES_DIR`, and
return the path, the number of bytes and the content type, never the file
contents.

`chunked` describes uploads split into several requests:

| Key | Meaning |
|---|---|
| `offset_field` | The field that carries each chunk's byte offset |
| `index_field` | The field that carries each chunk's number |
| `total_field` | The field that carries the total size |
| `chunk_size` | Bytes per chunk. Must be positive. |

It needs `chunk_size` and at least one of `offset_field` and `index_field`.
When analysis sees chunk-like requests it can't explain, it doesn't guess: it
sets `review: true` with a note.

### response

| Key | Meaning |
|---|---|
| `content_type` | The response's content type |
| `schema` | A JSON schema inferred from the recorded responses |
| `example` | One recorded response, with secrets redacted |

### source

| Key | Meaning |
|---|---|
| `key` | The merge key: method, normalized path and action value, such as `POST /module/api.php act=getdisklist`. |
| `steps` | The step names this operation was recorded in. |
| `samples` | How many requests it was built from. |
| `trigger` | The text of the button or link you clicked. |

`key` is how analysis recognizes the same operation in a new recording. Don't
change it.

## Editing a spec

Edit the spec in any text editor, then run `har2mcp generate` again. It
checks the spec first and lists every problem it finds. `har2mcp inspect`
prints a short summary of the result.

- **Rename a tool:** change `name`. Use a verb and a noun, like
  `list_disks`.
- **Improve a description:** change `description`. Say what the tool does on
  the device and anything Claude should know, such as units.
- **Switch a tool off:** set `enabled: false`. This is also how to get rid of
  a tool for good. If you delete it from the file instead, the next
  `analyze` adds it back.
- **Make a fixed value an input:** remove the value from `request.body` (or
  `request.query`) and add an input with `in: body` (or `in: query`) and
  `field` set to the key.
- **Make an input optional:** set `required: false`, or remove the line.
- **Change what counts as destructive:** change `kind`.
- **Fix the login:** when `auth.review` is `true`, read `auth.review_notes`,
  then correct `auth` by hand. Your version is kept when you analyze again.

## How analyzing again merges

When the output spec already exists, `har2mcp analyze` merges the new
analysis into it:

- Tools are matched on `source.key`.
- For `name`, `description`, `enabled`, `kind` and `inputs`, a value you
  changed by hand is kept, and an unchanged one takes the new value.
  `inputs` counts as one field: change any input and the whole list is kept.
- `request`, `response`, `source`, `file` and the review flags always come
  from the new analysis.
- The `auth` block works the same way, as one unit.
- New operations are added at the end. Tools missing from the new recordings
  are kept.
- `service.name` and `service.base_url` are kept. `service.hosts` gets any
  new hosts.
- Names stay unique: a name you chose wins, and a clashing name from analysis
  gets `_2`, `_3` and so on.

Hand edits are detected with the hashes under `generated` (and
`auth_generated`): if a field no longer matches the hash analysis stored, you
changed it. A tool without a `generated` block, such as one you wrote
yourself, keeps all five of those fields.

To undo your edits to a tool, delete the tool from the spec and analyze the
same recordings again. It comes back as analysis writes it.

If one of your edits no longer fits a new recording, for example an input for
a path placeholder that changed, the spec fails the checks below and the
error names the tool and field to fix.

## Validation

`har2mcp generate` and `har2mcp enhance` check the spec before they do
anything, refuse one that breaks these rules, and list every problem:

- `service.name` matches `^[a-z][a-z0-9_]{0,31}$`.
- `auth.mode` is `none`, `http` or `browser`. `http` and `browser` need
  `auth.login`. `browser` needs `auth.login.form` with the username and
  password selectors.
- In `http` mode the login request has an upper-case method and a path
  starting with `/`.
- Every token sets exactly one key in `from` and exactly one in `to`.
- `relogin_on` holds HTTP status codes (100 to 599).
- Tool names match `^[a-z][a-z0-9_]{0,63}$` and are unique.
- `kind` is `read`, `change` or `destructive`.
- `request.method` is upper case, `request.path` starts with `/`, and
  `body_type` is `none`, `json`, `form` or `multipart`.
- Input names match `^[A-Za-z][A-Za-z0-9_]{0,63}$` and are unique in their
  tool. `type` and `in` are from their lists.
- Every `{placeholder}` in a path has an `in: path` input, and every
  `in: path` input has a placeholder.
- A tool with `file` has exactly one `in: file` input, and only tools with
  `file` may have one. Uploads need `file.part`.
