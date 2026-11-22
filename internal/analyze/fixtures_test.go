package analyze

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/donaldsteele/har2mcp/internal/har"
)

// The fixtures model the fakenas API (see internal/fakenas and the plan's
// Task 2 table), so a real recording against fakenas analyzes the same way:
//
//	POST /api/login   {"username","password"} -> {"ok":true,"data":{"token":<csrf>}}
//	                  + Set-Cookie: NASSESSID=<id>; HttpOnly; Path=/
//	POST /api.php     {"act":...} + X-Csrf-Token + cookie
//	POST /api/upload  multipart: path, file
//	GET  /api/download?path=<nas path>  attachment
//	GET  /api/nonce   {"nonce":...} (scrambled-password variant)
const (
	fxBase     = "http://192.168.1.50"
	fxUser     = "admin"
	fxPassword = "hunter2-nas"
	fxSession  = "abc123"
	fxCSRF     = "csrf-7f3a9c2e1b44"
	fxNonce    = "9a8b7c6d5e4f"
)

var (
	fxDisks = map[string]any{"ok": true, "data": []any{
		map[string]any{"id": "sda", "model": "WD Red 4TB", "size_gb": 4000, "health": "good"},
		map[string]any{"id": "sdb", "model": "WD Red 4TB", "size_gb": 4000, "health": "good"},
	}}
	fxSysinfo = map[string]any{"ok": true, "data": map[string]any{"model": "F4-424", "version": "TOS 6.0.1", "uptime_s": 1234}}
	fxOK      = map[string]any{"ok": true}
)

// harBuilder builds HAR fixtures step by step:
//
//	newHAR(startURL).step("list disks").click("Disks").api("getdisklist", nil, resp)
type harBuilder struct {
	h      *har.HAR
	base   string
	clock  time.Time
	plain  bool   // a sanitized DevTools export: no _har2mcp, no cookies or auth headers, base64 bodies
	cur    string // label of the current step
	stepIx int
	trig   *har.Trigger
	cookie string // session cookie value once logged in
	csrf   string
}

// newHAR starts a har2mcp recording of the service at startURL.
func newHAR(startURL string) *harBuilder {
	u, _ := url.Parse(startURL)
	b := &harBuilder{
		h: &har.HAR{Log: har.Log{
			Version: "1.2",
			Creator: har.Creator{Name: "har2mcp", Version: "test"},
			Har2mcp: &har.Meta{Version: "test", StartURL: startURL},
		}},
		base:   u.Scheme + "://" + u.Host,
		clock:  time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC),
		stepIx: -1,
	}
	return b
}

// newDevToolsHAR starts a plain HAR as Chrome DevTools exports it with
// "Export HAR (sanitized)": no labels, no Cookie, Set-Cookie or Authorization
// headers, _resourceType on every entry and base64 response bodies.
func newDevToolsHAR(base string) *harBuilder {
	b := newHAR(base + "/")
	b.h.Log.Har2mcp = nil
	b.h.Log.Creator = har.Creator{Name: "WebInspector", Version: "537.36"}
	b.plain = true
	return b
}

func (b *harBuilder) build() *har.HAR {
	b.endStep()
	return b.h
}

func (b *harBuilder) tick() time.Time {
	b.clock = b.clock.Add(250 * time.Millisecond)
	return b.clock
}

// step starts a labeled step (ending the current one) with the values the
// user typed during it.
func (b *harBuilder) step(name string, typed ...har.TypedInput) *harBuilder {
	b.endStep()
	b.cur = name
	if m := b.h.Log.Har2mcp; m != nil {
		m.Steps = append(m.Steps, har.Step{Name: name, Start: b.tick(), Inputs: typed})
		b.stepIx = len(m.Steps) - 1
	}
	return b
}

func (b *harBuilder) endStep() *harBuilder {
	if m := b.h.Log.Har2mcp; m != nil && b.stepIx >= 0 {
		m.Steps[b.stepIx].End = b.tick()
	}
	b.cur, b.stepIx = "", -1
	return b
}

// click sets the trigger of the next request.
func (b *harBuilder) click(text string) *harBuilder {
	b.trig = &har.Trigger{Text: text, Role: "button", Selector: "#btn-" + strings.ToLower(strings.ReplaceAll(text, " ", "-"))}
	return b
}

func typed(label, name, selector, typ, value string) har.TypedInput {
	return har.TypedInput{Label: label, Name: name, Selector: selector, Type: typ, Value: value}
}

// req describes one request/response pair for add.
type req struct {
	method, url  string // url may be a path on the service
	reqMime      string
	reqBody      string
	params       []har.Param
	headers      []har.NameValue
	status       int
	respMime     string
	respBody     string
	respHeaders  []har.NameValue
	setCookies   []har.Cookie
	resourceType string
	noSession    bool
	failed       bool // no response (status 0)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// add appends an entry. API requests carry the session cookie and CSRF
// header once logged in, as the fakenas SPA sends them.
func (b *harBuilder) add(r req) *harBuilder {
	if r.status == 0 && !r.failed {
		r.status = 200
	}
	full := r.url
	if strings.HasPrefix(full, "/") {
		full = b.base + full
	}
	u, err := url.Parse(full)
	if err != nil {
		panic(err)
	}
	e := har.Entry{
		StartedDateTime: b.tick(),
		Time:            12,
		Request: har.Request{
			Method:      r.method,
			URL:         full,
			HTTPVersion: "HTTP/1.1",
			Headers: append([]har.NameValue{
				{Name: "Host", Value: u.Host},
				{Name: "User-Agent", Value: "Mozilla/5.0 (X11; Linux x86_64) Chrome/142.0"},
				{Name: "Accept", Value: "*/*"},
			}, r.headers...),
			HeadersSize: -1,
			BodySize:    int64(len(r.reqBody)),
		},
		Response: har.Response{
			Status:      r.status,
			StatusText:  "OK",
			HTTPVersion: "HTTP/1.1",
			Headers:     append([]har.NameValue{{Name: "Content-Type", Value: r.respMime}}, r.respHeaders...),
			Content:     har.Content{Size: int64(len(r.respBody)), MimeType: r.respMime, Text: r.respBody},
			HeadersSize: -1,
			BodySize:    int64(len(r.respBody)),
		},
		Step: b.cur,
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			e.Request.QueryString = append(e.Request.QueryString, har.NameValue{Name: k, Value: v})
		}
	}
	if r.reqMime != "" {
		e.Request.Headers = append(e.Request.Headers, har.NameValue{Name: "Content-Type", Value: r.reqMime})
		e.Request.PostData = &har.PostData{MimeType: r.reqMime, Text: r.reqBody, Params: r.params}
	}
	if b.cookie != "" && !r.noSession {
		e.Request.Headers = append(e.Request.Headers, har.NameValue{Name: "X-Csrf-Token", Value: b.csrf})
		if !b.plain {
			e.Request.Headers = append(e.Request.Headers, har.NameValue{Name: "Cookie", Value: "NASSESSID=" + b.cookie})
			e.Request.Cookies = []har.Cookie{{Name: "NASSESSID", Value: b.cookie}}
		}
	}
	for _, c := range r.setCookies {
		if b.plain {
			continue
		}
		e.Response.Headers = append(e.Response.Headers, har.NameValue{Name: "Set-Cookie", Value: c.Name + "=" + c.Value + "; HttpOnly; Path=/"})
		e.Response.Cookies = append(e.Response.Cookies, c)
	}
	if b.plain {
		e.ResourceType = r.resourceType
		if e.ResourceType == "" {
			e.ResourceType = "fetch"
		}
		if r.respBody != "" {
			e.Response.Content.Text = base64.StdEncoding.EncodeToString([]byte(r.respBody))
			e.Response.Content.Encoding = "base64"
		}
	} else if r.resourceType != "" {
		e.ResourceType = r.resourceType
	}
	if b.trig != nil {
		e.Trigger = b.trig
		b.trig = nil
	}
	b.h.Log.Entries = append(b.h.Log.Entries, e)
	return b
}

func (b *harBuilder) get(path string, resp any) *harBuilder {
	return b.add(req{method: "GET", url: path, respMime: "application/json", respBody: mustJSON(resp)})
}

func (b *harBuilder) post(path string, body, resp any) *harBuilder {
	return b.add(req{method: "POST", url: path, reqMime: "application/json", reqBody: mustJSON(body),
		respMime: "application/json", respBody: mustJSON(resp)})
}

// api posts {"act": act, ...extra} to /api.php.
func (b *harBuilder) api(act string, extra map[string]any, resp any) *harBuilder {
	body := map[string]any{"act": act}
	for k, v := range extra {
		body[k] = v
	}
	return b.post("/api.php", body, resp)
}

// apiStatus posts an act that fails with the given status and body.
func (b *harBuilder) apiStatus(act string, status int, resp any) *harBuilder {
	return b.add(req{method: "POST", url: "/api.php", reqMime: "application/json", reqBody: mustJSON(map[string]any{"act": act}),
		status: status, respMime: "application/json", respBody: mustJSON(resp)})
}

// static adds the SPA shell: the page, its script, stylesheet and logo.
func (b *harBuilder) static() *harBuilder {
	b.add(req{method: "GET", url: "/", respMime: "text/html", respBody: "<!doctype html><html><body><div id=app></div></body></html>", resourceType: "document"})
	b.add(req{method: "GET", url: "/static/app.js", respMime: "application/javascript", respBody: "fetch('/api.php')", resourceType: "script"})
	b.add(req{method: "GET", url: "/static/style.css", respMime: "text/css", respBody: "body{}", resourceType: "stylesheet"})
	b.add(req{method: "GET", url: "/static/logo.png", respMime: "image/png", respBody: "\x89PNG", resourceType: "image"})
	return b
}

// login records the fakenas login: the typed values in the step, the
// login_submit capture, and the request.
func (b *harBuilder) login(user, password string) *harBuilder {
	return b.loginSending(user, password, password)
}

// loginSending records a login where the page sends sentPassword (which
// differs from the typed password when the page scrambles it).
func (b *harBuilder) loginSending(user, password, sentPassword string) *harBuilder {
	if m := b.h.Log.Har2mcp; m != nil {
		if b.stepIx >= 0 {
			s := &m.Steps[b.stepIx]
			s.Inputs = append(s.Inputs,
				typed("Username", "username", "#username", "text", user),
				typed("Password", "password", "#password", "password", password))
		}
		m.Login = &har.LoginCapture{
			PageURL:          b.base + "/",
			UsernameSelector: "#username",
			PasswordSelector: "#password",
			SubmitSelector:   "#login",
			Username:         user,
			Password:         password,
		}
	}
	b.click("Log in")
	b.add(req{method: "POST", url: "/api/login", reqMime: "application/json",
		reqBody:  mustJSON(map[string]any{"username": user, "password": sentPassword}),
		respMime: "application/json", respBody: mustJSON(map[string]any{"ok": true, "data": map[string]any{"token": fxCSRF}}),
		setCookies: []har.Cookie{{Name: "NASSESSID", Value: fxSession, Path: "/", HTTPOnly: true}},
	})
	b.cookie, b.csrf = fxSession, fxCSRF
	return b
}

// upload posts a multipart upload of one file into folder.
func (b *harBuilder) upload(folder, filename, content string) *harBuilder {
	const boundary = "----WebKitFormBoundaryX3k9"
	body := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n" + folder +
		"\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + filename +
		"\"\r\nContent-Type: text/plain\r\n\r\n" + content + "\r\n--" + boundary + "--\r\n"
	return b.add(req{method: "POST", url: "/api/upload", reqMime: "multipart/form-data; boundary=" + boundary, reqBody: body,
		params: []har.Param{
			{Name: "path", Value: folder},
			{Name: "file", FileName: filename, ContentType: "text/plain", Value: content},
		},
		respMime: "application/json", respBody: mustJSON(fxOK)})
}

// download fetches a NAS file as an attachment.
func (b *harBuilder) download(path, content string) *harBuilder {
	base := path[strings.LastIndexByte(path, '/')+1:]
	return b.add(req{method: "GET", url: "/api/download?path=" + url.QueryEscape(path),
		respMime:    "application/octet-stream",
		respBody:    content,
		respHeaders: []har.NameValue{{Name: "Content-Disposition", Value: `attachment; filename="` + base + `"`}},
	})
}

// sysinfoPoll is the SPA's 5-second background poll: no step, no trigger.
func (b *harBuilder) sysinfoPoll() *harBuilder {
	return b.api("getsysinfo", nil, fxSysinfo)
}

// fakenasRecording is a full labeled session against fakenas, as Task 2's
// recorder script and Task 5's e2e test drive it.
func fakenasRecording() *harBuilder {
	b := newHAR(fxBase + "/")
	b.static()
	// The SPA checks for a session on load, before anyone logs in.
	b.apiStatus("getsysinfo", 401, map[string]any{"ok": false, "error": "not logged in"})
	b.step("login").login(fxUser, fxPassword).endStep()
	b.sysinfoPoll()
	b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks)
	b.sysinfoPoll().endStep()
	b.step("add share", typed("Share name", "share-name", "#share-name", "text", "media")).
		click("Add share").api("addshare", map[string]any{"name": "media"}, fxOK).endStep()
	b.step("upload file", typed("Folder", "upload-path", "#upload-path", "text", "/public")).
		click("Upload").upload("/public", "hello.txt", "hi").endStep()
	b.sysinfoPoll()
	b.step("download file").click("hello.txt").download("/public/hello.txt", "hi").endStep()
	b.step("delete share").click("Delete").api("delshare", map[string]any{"name": "media"}, fxOK).endStep()
	b.step("reboot").click("Reboot").api("reboot", nil, fxOK).endStep()
	b.sysinfoPoll()
	return b
}

// fakenasScrambledRecording is the Scramble variant: the page fetches a nonce
// and sends sha256hex(password+":"+nonce) instead of the password.
func fakenasScrambledRecording() *harBuilder {
	b := newHAR(fxBase + "/")
	b.static()
	b.step("login")
	b.get("/api/nonce", map[string]any{"nonce": fxNonce})
	b.loginSending(fxUser, fxPassword, scramble(fxPassword, fxNonce)).endStep()
	b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks).endStep()
	b.sysinfoPoll()
	return b
}

func scramble(password, nonce string) string {
	sum := sha256.Sum256([]byte(password + ":" + nonce))
	return hex.EncodeToString(sum[:])
}
