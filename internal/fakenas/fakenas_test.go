package fakenas

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// client is a tiny HTTP client for the fakenas API that keeps the session
// cookie and the CSRF token the way the SPA does.
type client struct {
	t     *testing.T
	base  string
	http  *http.Client
	token string
}

func newClient(t *testing.T, s *Server) *client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Jar: jar}
	if s.ts.TLS != nil {
		hc = s.ts.Client()
		hc.Jar = jar
	}
	return &client{t: t, base: s.URL, http: hc}
}

// do sends a request and returns the status, the decoded JSON body (nil when
// the body is not JSON) and the response.
func (c *client) do(req *http.Request) (int, map[string]any, *http.Response, []byte) {
	c.t.Helper()
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	var m map[string]any
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(body, &m); err != nil {
			c.t.Fatalf("bad JSON %q: %v", body, err)
		}
	}
	return resp.StatusCode, m, resp, body
}

func (c *client) postJSON(path string, v any, headers map[string]string) (int, map[string]any) {
	c.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		c.t.Fatal(err)
	}
	req, err := http.NewRequest("POST", c.base+path, bytes.NewReader(b))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	status, m, _, _ := c.do(req)
	return status, m
}

func (c *client) login(user, password string) (int, map[string]any) {
	c.t.Helper()
	status, m := c.postJSON("/api/login", map[string]string{"username": user, "password": password}, nil)
	if status == 200 {
		data, _ := m["data"].(map[string]any)
		c.token, _ = data["token"].(string)
		if c.token == "" {
			c.t.Fatalf("login response has no data.token: %v", m)
		}
	}
	return status, m
}

func (c *client) act(act string, extra map[string]any) (int, map[string]any) {
	c.t.Helper()
	body := map[string]any{"act": act}
	for k, v := range extra {
		body[k] = v
	}
	return c.postJSON("/api.php", body, map[string]string{"X-Csrf-Token": c.token})
}

func mustLogin(t *testing.T, s *Server) *client {
	t.Helper()
	c := newClient(t, s)
	if status, m := c.login(DefaultUser, DefaultPassword); status != 200 {
		t.Fatalf("login: %d %v", status, m)
	}
	return c
}

func TestLoginAndAct(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := newClient(t, s)

	status, m := c.login("admin", "hunter2-nas")
	if status != 200 || m["ok"] != true {
		t.Fatalf("login: %d %v", status, m)
	}
	u, _ := url.Parse(s.URL)
	var sess *http.Cookie
	for _, ck := range c.http.Jar.Cookies(u) {
		if ck.Name == "NASSESSID" {
			sess = ck
		}
	}
	if sess == nil || sess.Value == "" {
		t.Fatal("login did not set the NASSESSID cookie")
	}

	status, m = c.act("getdisklist", nil)
	if status != 200 || m["ok"] != true {
		t.Fatalf("getdisklist: %d %v", status, m)
	}
	disks, _ := m["data"].([]any)
	if len(disks) != 2 {
		t.Fatalf("want 2 disks, got %v", m["data"])
	}
	d0 := disks[0].(map[string]any)
	want := map[string]any{"id": "sda", "model": "WD Red 4TB", "size_gb": float64(4000), "health": "good"}
	if !reflect.DeepEqual(d0, want) {
		t.Errorf("disk 0 = %v, want %v", d0, want)
	}
}

func TestLoginCookieAttributes(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := newClient(t, s)
	req, _ := http.NewRequest("POST", s.URL+"/api/login", strings.NewReader(`{"username":"admin","password":"hunter2-nas"}`))
	req.Header.Set("Content-Type", "application/json")
	_, _, resp, _ := c.do(req)
	sc := resp.Header.Get("Set-Cookie")
	for _, want := range []string{"NASSESSID=", "HttpOnly", "Path=/"} {
		if !strings.Contains(sc, want) {
			t.Errorf("Set-Cookie %q lacks %q", sc, want)
		}
	}
}

func TestBadCredentials(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := newClient(t, s)
	for _, tc := range []struct{ user, pw string }{
		{"admin", "wrong"},
		{"root", "hunter2-nas"},
		{"", ""},
	} {
		status, m := c.login(tc.user, tc.pw)
		if status != 401 || m["ok"] != false || m["error"] != "bad credentials" {
			t.Errorf("login(%q,%q) = %d %v, want 401 bad credentials", tc.user, tc.pw, status, m)
		}
	}
}

func TestCustomCredentials(t *testing.T) {
	s := Start(Config{User: "ops", Password: "s3cret"})
	defer s.Close()
	c := newClient(t, s)
	if status, _ := c.login("admin", "hunter2-nas"); status != 401 {
		t.Errorf("default credentials accepted with custom config: %d", status)
	}
	if status, m := c.login("ops", "s3cret"); status != 200 {
		t.Errorf("custom credentials rejected: %d %v", status, m)
	}
}

func TestNoSessionIs401(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := newClient(t, s)
	status, m := c.act("getdisklist", nil)
	if status != 401 || m["ok"] != false || m["error"] != "not logged in" {
		t.Fatalf("got %d %v, want 401 not logged in", status, m)
	}
	// A made-up cookie is no session either.
	req, _ := http.NewRequest("POST", s.URL+"/api.php", strings.NewReader(`{"act":"getdisklist"}`))
	req.AddCookie(&http.Cookie{Name: "NASSESSID", Value: "forged"})
	if status, _, _, _ := c.do(req); status != 401 {
		t.Errorf("forged session: got %d, want 401", status)
	}
}

func TestBadCSRFIs403(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := mustLogin(t, s)
	good := c.token
	for _, tok := range []string{"", "wrong-token"} {
		c.token = tok
		status, m := c.act("getdisklist", nil)
		if status != 403 || m["ok"] != false || m["error"] != "bad token" {
			t.Errorf("token %q: got %d %v, want 403 bad token", tok, status, m)
		}
	}
	c.token = good
	if status, _ := c.act("getdisklist", nil); status != 200 {
		t.Errorf("good token: got %d", status)
	}
}

func TestExpireSessions(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := mustLogin(t, s)
	if status, _ := c.act("getdisklist", nil); status != 200 {
		t.Fatalf("before expiry: %d", status)
	}
	s.ExpireSessions()
	status, m := c.act("getdisklist", nil)
	if status != 401 || m["error"] != "not logged in" {
		t.Fatalf("after expiry: got %d %v, want 401", status, m)
	}
	// Logging in again works.
	if status, _ := c.login(DefaultUser, DefaultPassword); status != 200 {
		t.Fatalf("relogin: %d", status)
	}
	if status, _ := c.act("getdisklist", nil); status != 200 {
		t.Fatalf("after relogin: %d", status)
	}
}

func TestSharesAndSysinfo(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := mustLogin(t, s)

	status, m := c.act("getsharelist", nil)
	if status != 200 || !reflect.DeepEqual(m["data"], []any{"public"}) {
		t.Fatalf("initial shares: %d %v", status, m)
	}
	if status, m := c.act("addshare", map[string]any{"name": "media"}); status != 200 || m["ok"] != true {
		t.Fatalf("addshare: %d %v", status, m)
	}
	if status, m := c.act("addshare", map[string]any{"name": "backups"}); status != 200 || m["ok"] != true {
		t.Fatalf("addshare: %d %v", status, m)
	}
	if got := s.Shares(); !reflect.DeepEqual(got, []string{"backups", "media", "public"}) {
		t.Errorf("Shares() = %v", got)
	}
	if status, _ := c.act("addshare", map[string]any{"name": "media"}); status != 409 {
		t.Errorf("duplicate addshare: got %d, want 409", status)
	}
	for _, bad := range []any{"", "a/b", "../x", nil, 7} {
		if status, _ := c.act("addshare", map[string]any{"name": bad}); status != 400 {
			t.Errorf("addshare %v: got %d, want 400", bad, status)
		}
	}
	if status, m := c.act("delshare", map[string]any{"name": "media"}); status != 200 || m["ok"] != true {
		t.Fatalf("delshare: %d %v", status, m)
	}
	if status, _ := c.act("delshare", map[string]any{"name": "media"}); status != 404 {
		t.Errorf("delshare of a missing share: got %d, want 404", status)
	}
	status, m = c.act("getsharelist", nil)
	if status != 200 || !reflect.DeepEqual(m["data"], []any{"backups", "public"}) {
		t.Errorf("shares after delete: %v", m)
	}

	status, m = c.act("getsysinfo", nil)
	info, _ := m["data"].(map[string]any)
	if status != 200 || info["model"] != "F4-424" || info["version"] != "TOS 6.0.1" {
		t.Errorf("getsysinfo: %d %v", status, m)
	}
	if _, ok := info["uptime_s"].(float64); !ok {
		t.Errorf("getsysinfo has no numeric uptime_s: %v", info)
	}

	if s.Rebooted() {
		t.Fatal("Rebooted before reboot")
	}
	if status, m := c.act("reboot", nil); status != 200 || m["ok"] != true {
		t.Fatalf("reboot: %d %v", status, m)
	}
	if !s.Rebooted() {
		t.Error("reboot did not set the flag")
	}

	if status, m := c.act("nosuchact", nil); status != 400 || m["ok"] != false {
		t.Errorf("unknown act: %d %v", status, m)
	}
}

func TestBadRequests(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := mustLogin(t, s)

	req, _ := http.NewRequest("POST", s.URL+"/api.php", strings.NewReader("{not json"))
	req.Header.Set("X-Csrf-Token", c.token)
	if status, m, _, _ := c.do(req); status != 400 || m["ok"] != false {
		t.Errorf("bad JSON: %d %v", status, m)
	}
	req, _ = http.NewRequest("GET", s.URL+"/api.php", nil)
	if status, _, _, _ := c.do(req); status != 405 {
		t.Errorf("GET /api.php: %d, want 405", status)
	}
	req, _ = http.NewRequest("GET", s.URL+"/api/login", nil)
	if status, _, _, _ := c.do(req); status != 405 {
		t.Errorf("GET /api/login: %d, want 405", status)
	}
	req, _ = http.NewRequest("GET", s.URL+"/nope", nil)
	if status, _, _, _ := c.do(req); status != 404 {
		t.Errorf("GET /nope: %d, want 404", status)
	}
}

// upload posts a multipart form the way the SPA does.
func (c *client) upload(folder, name string, data []byte) (int, map[string]any) {
	c.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("path", folder); err != nil {
		c.t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		c.t.Fatal(err)
	}
	fw.Write(data)
	mw.Close()
	req, _ := http.NewRequest("POST", c.base+"/api/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Csrf-Token", c.token)
	status, m, _, _ := c.do(req)
	return status, m
}

func (c *client) download(path string) (int, *http.Response, []byte) {
	c.t.Helper()
	req, _ := http.NewRequest("GET", c.base+"/api/download?path="+url.QueryEscape(path), nil)
	req.Header.Set("X-Csrf-Token", c.token)
	status, _, resp, body := c.do(req)
	return status, resp, body
}

func TestUploadDownload(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := mustLogin(t, s)

	if status, m := c.upload("/public", "hello.txt", []byte("hi")); status != 200 || m["ok"] != true {
		t.Fatalf("upload: %d %v", status, m)
	}
	if got := string(s.Files()["/public/hello.txt"]); got != "hi" {
		t.Fatalf(`Files()["/public/hello.txt"] = %q, want "hi"`, got)
	}

	status, resp, body := c.download("/public/hello.txt")
	if status != 200 || string(body) != "hi" {
		t.Fatalf("download: %d %q", status, body)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != `attachment; filename="hello.txt"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q", ct)
	}

	// PutFile and a binary round trip.
	bin := []byte{0, 1, 2, 0xff, 0xfe}
	s.PutFile("/public/b.bin", bin)
	if status, _, body := c.download("/public/b.bin"); status != 200 || !bytes.Equal(body, bin) {
		t.Errorf("download b.bin: %d %v", status, body)
	}
	if status, _, _ := c.download("/public/missing"); status != 404 {
		t.Errorf("missing file: %d, want 404", status)
	}

	// Files returns a copy.
	s.Files()["/public/hello.txt"][0] = 'X'
	if got := string(s.Files()["/public/hello.txt"]); got != "hi" {
		t.Errorf("Files() is not a copy: %q", got)
	}
}

func TestUploadDownloadAuth(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := mustLogin(t, s)
	good := c.token
	c.token = "bad"
	if status, _ := c.upload("/public", "x.txt", []byte("x")); status != 403 {
		t.Errorf("upload with a bad token: %d, want 403", status)
	}
	if status, _, _ := c.download("/public/x.txt"); status != 403 {
		t.Errorf("download with a bad token: %d, want 403", status)
	}
	c.token = good
	s.ExpireSessions()
	if status, _ := c.upload("/public", "x.txt", []byte("x")); status != 401 {
		t.Errorf("upload without a session: %d, want 401", status)
	}
	if status, _, _ := c.download("/public/x.txt"); status != 401 {
		t.Errorf("download without a session: %d, want 401", status)
	}
	if len(s.Files()) != 0 {
		t.Errorf("rejected uploads stored files: %v", s.Files())
	}
}

func TestUploadBadForms(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := mustLogin(t, s)
	if status, _ := c.upload("relative", "x.txt", []byte("x")); status != 400 {
		t.Errorf("relative folder: %d, want 400", status)
	}
	if status, _ := c.upload("/public", "", []byte("x")); status != 400 {
		t.Errorf("empty file name: %d, want 400", status)
	}
	// A file name with a path keeps only its base name.
	if status, _ := c.upload("/public/../public", "../../evil.txt", []byte("e")); status != 200 {
		t.Fatalf("upload: %d", status)
	}
	if _, ok := s.Files()["/public/evil.txt"]; !ok {
		t.Errorf("file not stored under its base name: %v", s.Files())
	}
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (c *client) nonce() string {
	c.t.Helper()
	req, _ := http.NewRequest("GET", c.base+"/api/nonce", nil)
	status, m, _, _ := c.do(req)
	n, _ := m["nonce"].(string)
	if status != 200 || len(n) < 16 {
		c.t.Fatalf("nonce: %d %v", status, m)
	}
	return n
}

func TestScrambleRejectsPlain(t *testing.T) {
	s := Start(Config{Scramble: true})
	defer s.Close()
	c := newClient(t, s)

	if status, m := c.login("admin", "hunter2-nas"); status != 401 {
		t.Fatalf("plain password with Scramble: %d %v, want 401", status, m)
	}
	n := c.nonce()
	if status, _ := c.login("admin", sha256hex("wrong:"+n)); status != 401 {
		t.Fatalf("wrong scrambled password accepted")
	}
	if status, m := c.login("admin", sha256hex("hunter2-nas:"+n)); status != 200 {
		t.Fatalf("scrambled password: %d %v, want 200", status, m)
	}
	if status, _ := c.act("getdisklist", nil); status != 200 {
		t.Fatalf("act after scrambled login: %d", status)
	}
	// A nonce works once.
	c2 := newClient(t, s)
	if status, _ := c2.login("admin", sha256hex("hunter2-nas:"+n)); status != 401 {
		t.Errorf("replayed nonce accepted")
	}
}

func TestNonceWithoutScramble(t *testing.T) {
	s := Start(Config{})
	defer s.Close()
	c := newClient(t, s)
	n := c.nonce()
	if n == c.nonce() {
		t.Error("two nonces are equal")
	}
	// Without Scramble the plain password is what counts.
	if status, _ := c.login("admin", sha256hex("hunter2-nas:"+n)); status != 401 {
		t.Error("scrambled password accepted without Scramble")
	}
}

func TestSPAFiles(t *testing.T) {
	for _, scramble := range []bool{false, true} {
		s := Start(Config{Scramble: scramble})
		c := newClient(t, s)
		req, _ := http.NewRequest("GET", s.URL+"/", nil)
		status, _, resp, body := c.do(req)
		if status != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("GET /: %d %s", status, resp.Header.Get("Content-Type"))
		}
		html := string(body)
		for _, id := range []string{
			`id="username"`, `id="password"`, `id="login"`,
			`id="btn-disks"`, `id="btn-sysinfo"`, `id="btn-shares"`,
			`id="share-name"`, `id="btn-add-share"`, `id="btn-reboot"`,
			`id="upload-path"`, `id="upload-file"`, `id="btn-upload"`, `id="out"`,
			`/static/app.js`, `/static/style.css`, `/static/logo.png`,
		} {
			if !strings.Contains(html, id) {
				t.Errorf("index.html lacks %s", id)
			}
		}
		wantMode := `data-scramble="0"`
		if scramble {
			wantMode = `data-scramble="1"`
		}
		if !strings.Contains(html, wantMode) {
			t.Errorf("index.html lacks %s", wantMode)
		}
		for path, ctype := range map[string]string{
			"/static/app.js":    "text/javascript",
			"/static/style.css": "text/css",
			"/static/logo.png":  "image/png",
		} {
			req, _ := http.NewRequest("GET", s.URL+path, nil)
			status, _, resp, body := c.do(req)
			if status != 200 || len(body) == 0 || !strings.HasPrefix(resp.Header.Get("Content-Type"), ctype) {
				t.Errorf("GET %s: %d %q (%d bytes)", path, status, resp.Header.Get("Content-Type"), len(body))
			}
		}
		js := func() string {
			req, _ := http.NewRequest("GET", s.URL+"/static/app.js", nil)
			_, _, _, b := c.do(req)
			return string(b)
		}()
		for _, sel := range []string{"del-share", "data-name", "download", "data-path", "getsysinfo", "5000", "X-Csrf-Token", "/api/nonce"} {
			if !strings.Contains(js, sel) {
				t.Errorf("app.js lacks %q", sel)
			}
		}
		s.Close()
	}
}

func TestTLS(t *testing.T) {
	s := Start(Config{TLS: true})
	defer s.Close()
	if !strings.HasPrefix(s.URL, "https://") {
		t.Fatalf("URL = %q, want https", s.URL)
	}
	c := mustLogin(t, s)
	if status, _ := c.act("getdisklist", nil); status != 200 {
		t.Fatalf("getdisklist over TLS: %d", status)
	}
}

func TestDefaults(t *testing.T) {
	if DefaultUser != "admin" || DefaultPassword != "hunter2-nas" {
		t.Fatalf("defaults = %q/%q", DefaultUser, DefaultPassword)
	}
}
