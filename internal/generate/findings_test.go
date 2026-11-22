package generate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/har2mcp/internal/spec"
)

// Tests for the issues found in the independent review of v0.1.0.

// serveMore serves the fake device's extra endpoints. It reports whether it
// handled the request.
func (f *fakeAPI) serveMore(w http.ResponseWriter, r *http.Request) bool {
	sessionToken := func() (string, bool) {
		c, err := r.Cookie("NASSESSID")
		if err != nil {
			return "", false
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		t, ok := f.sessions[c.Value]
		return t, ok
	}
	switch {
	case r.URL.Path == "/api/session":
		// The CSRF token comes from here, not from the login response.
		t, ok := sessionToken()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "not logged in"})
			return true
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": f.user, "csrfToken": t})
	case r.URL.Path == "/api/sid":
		// The same, as XML.
		t, ok := sessionToken()
		if !ok {
			t = "0000000000000000"
		}
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>%s</SID><Challenge>x</Challenge></SessionInfo>`, t)
	case strings.HasPrefix(r.URL.Path, "/luci/;stok="):
		// The session token in the URL path, as OpenWrt LuCI does.
		tok := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/luci/;stok="), "/status")
		f.mu.Lock()
		ok := false
		for _, t := range f.sessions {
			ok = ok || t == tok
		}
		f.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "not logged in"})
			return true
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stok": "valid"})
	case r.URL.Path == "/basic/status":
		f.mu.Lock()
		f.basicCalls++
		f.mu.Unlock()
		if u, p, ok := r.BasicAuth(); !ok || u != f.user || p != f.password {
			w.Header().Set("WWW-Authenticate", `Basic realm="cam"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false})
			return true
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "model": "cam-2"})
	case r.URL.Path == "/api/chunk":
		if !f.authorized(w, r) {
			return true
		}
		n := r.FormValue("n")
		file, _, err := r.FormFile("file")
		if err != nil || n == "" || n == "0" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad chunk " + n})
			return true
		}
		data, _ := io.ReadAll(file)
		file.Close()
		f.mu.Lock()
		if f.chunks == nil {
			f.chunks = map[string]string{}
		}
		f.chunks[n] = string(data)
		f.chunkTotal = r.FormValue("total")
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case r.URL.Path == "/api/echo":
		if !f.authorized(w, r) {
			return true
		}
		f.mu.Lock()
		f.lastQuery = r.URL.RawQuery
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		return false
	}
	return true
}

func nasEnv(srv string, extra ...string) []string {
	return append([]string{"NAS_URL=" + srv, "NAS_USER=admin", "NAS_PASSWORD=hunter2-nas"}, extra...)
}

// A CSRF token from GET /api/session (JSON) or GET /api/sid (XML): the
// server makes that request after logging in, and again after logging in
// again.
func TestGeneratedServerTokenRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a generated server")
	}
	for _, c := range []struct {
		name string
		from spec.TokenRef
		path string
	}{
		{"json", spec.TokenRef{ResponseJSON: "csrfToken"}, "/api/session"},
		{"xml", spec.TokenRef{ResponseText: `<SID>([0-9a-f]+)</SID>`}, "/api/sid"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			api, srv := newFakeAPI(false)
			defer srv.Close()
			s := httpSpec()
			s.Service.BaseURL = ""
			s.Auth.Session.Tokens = []spec.TokenFlow{{Name: "csrf", From: c.from, To: spec.TokenRef{Header: "X-Csrf-Token"},
				Request: &spec.Request{Method: "GET", Path: c.path}}}
			s.Tools = s.Tools[:2]
			bin := buildServer(t, s)
			cs := connect(t, bin, nasEnv(srv.URL, "NAS_FILES_DIR="+t.TempDir())...)
			if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
				t.Fatalf("list_disks = %s", text)
			}
			mustOK(t, cs, "add_share", map[string]any{"name": "media"})
			api.expire()
			if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
				t.Fatalf("list_disks after expiry = %s", text)
			}
		})
	}
}

// The session token in the URL path.
func TestGeneratedServerPathToken(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a generated server")
	}
	t.Parallel()
	api, srv := newFakeAPI(false)
	defer srv.Close()
	s := httpSpec()
	s.Service.BaseURL = ""
	s.Auth.Session.Tokens = append(s.Auth.Session.Tokens, spec.TokenFlow{Name: "stok", From: spec.TokenRef{ResponseJSON: "data.token"}, To: spec.TokenRef{Path: "stok"}})
	s.Tools = []spec.Tool{{
		Name: "router_status", Description: "Router status.", Enabled: true, Kind: "read",
		Request: spec.Request{Method: "GET", Path: "/luci/;stok={stok}/status", BodyType: "none"},
		Inputs:  []spec.Input{},
		Source:  spec.Source{Key: "GET /luci/;stok={stok}/status", Samples: 1},
	}}
	bin := buildServer(t, s)
	cs := connect(t, bin, nasEnv(srv.URL, "NAS_FILES_DIR="+t.TempDir())...)
	if text := mustOK(t, cs, "router_status", nil); !strings.Contains(text, "valid") {
		t.Fatalf("router_status = %s", text)
	}
	api.expire()
	if text := mustOK(t, cs, "router_status", nil); !strings.Contains(text, "valid") {
		t.Fatalf("router_status after expiry = %s", text)
	}
}

// HTTP Basic auth: every request carries the credentials, and a 401 is not
// retried.
func TestGeneratedServerBasicAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a generated server")
	}
	t.Parallel()
	api, srv := newFakeAPI(false)
	defer srv.Close()
	s := &spec.Spec{
		Har2mcp: spec.FormatVersion,
		Service: spec.Service{Name: "nas"},
		Auth:    spec.Auth{Mode: "basic"},
		Tools: []spec.Tool{{
			Name: "camera_status", Description: "Camera status.", Enabled: true, Kind: "read",
			Request: spec.Request{Method: "GET", Path: "/basic/status", BodyType: "none"},
			Inputs:  []spec.Input{},
			Source:  spec.Source{Key: "GET /basic/status", Samples: 1},
		}},
	}
	bin := buildServer(t, s)
	cs := connect(t, bin, nasEnv(srv.URL)...)
	if text := mustOK(t, cs, "camera_status", nil); !strings.Contains(text, "cam-2") {
		t.Fatalf("camera_status = %s", text)
	}
	bad := connect(t, bin, "NAS_URL="+srv.URL, "NAS_USER=admin", "NAS_PASSWORD=wrong")
	api.mu.Lock()
	before := api.basicCalls
	api.mu.Unlock()
	if text := mustErr(t, bad, "camera_status", nil); !strings.Contains(text, "401") {
		t.Fatalf("wrong password = %s", text)
	}
	api.mu.Lock()
	calls := api.basicCalls - before
	api.mu.Unlock()
	if calls != 1 {
		t.Errorf("a 401 with Basic auth was sent %d times, want 1", calls)
	}
}

// After a failed login the server does not try again for a while, so a
// wrong password cannot lock the account; and a session that fails right
// after a login does not trigger a second login in the same call.
func TestGeneratedServerLoginBackoff(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a generated server")
	}
	t.Parallel()
	api, srv := newFakeAPI(false)
	defer srv.Close()
	s := httpSpec()
	s.Service.BaseURL = ""
	s.Tools = s.Tools[:1]
	bin := buildServer(t, s)
	bad := connect(t, bin, "NAS_URL="+srv.URL, "NAS_USER=admin", "NAS_PASSWORD=wrong")
	var last string
	for i := 0; i < 3; i++ {
		last = mustErr(t, bad, "list_disks", nil)
	}
	api.mu.Lock()
	attempts := api.loginAttempts
	api.mu.Unlock()
	if attempts != 1 {
		t.Errorf("3 calls with a wrong password made %d login attempts, want 1", attempts)
	}
	if !strings.Contains(last, "401") || !strings.Contains(last, "lock") {
		t.Errorf("third error = %s", last)
	}

	// The login works, but the spec lacks the CSRF token, so every call
	// gets 403: the call right after the login does not log in again.
	s.Auth.Session.Tokens = nil
	noToken := buildServer(t, s)
	cs := connect(t, noToken, nasEnv(srv.URL)...)
	api.mu.Lock()
	before := api.loginAttempts
	api.mu.Unlock()
	if text := mustErr(t, cs, "list_disks", nil); !strings.Contains(text, "403") {
		t.Fatalf("list_disks = %s", text)
	}
	api.mu.Lock()
	attempts = api.loginAttempts - before
	api.mu.Unlock()
	if attempts != 1 {
		t.Errorf("one call made %d login attempts, want 1", attempts)
	}
}

// Chunk indexes that start at 1 (resumable.js, flow.js).
func TestGeneratedServerChunkIndexBase(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a generated server")
	}
	t.Parallel()
	api, srv := newFakeAPI(false)
	defer srv.Close()
	s := httpSpec()
	s.Service.BaseURL = ""
	s.Tools = []spec.Tool{{
		Name: "upload_chunked", Description: "Upload in chunks.", Enabled: true, Kind: "change",
		Request: spec.Request{Method: "POST", Path: "/api/chunk", BodyType: "multipart", Body: map[string]any{"path": "/public"}},
		File:    &spec.FileOp{Direction: "upload", Part: "file", Chunked: &spec.Chunking{IndexField: "n", TotalField: "total", ChunkSize: 4, IndexBase: 1}},
		Inputs:  []spec.Input{{Name: "local_path", Type: "string", Required: true, In: "file", Field: "file"}},
		Source:  spec.Source{Key: "POST /api/chunk", Samples: 3},
	}}
	bin := buildServer(t, s)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := connect(t, bin, nasEnv(srv.URL, "NAS_FILES_DIR="+dir)...)
	mustOK(t, cs, "upload_chunked", map[string]any{"local_path": "big.bin"})
	api.mu.Lock()
	defer api.mu.Unlock()
	want := map[string]string{"1": "0123", "2": "4567", "3": "89"}
	if fmt.Sprint(api.chunks) != fmt.Sprint(want) || api.chunkTotal != "10" {
		t.Errorf("chunks = %v total %q, want %v total 10", api.chunks, api.chunkTotal, want)
	}
}

// Cache-busting query parameters get the current time (or a random number)
// on every call.
func TestGeneratedServerCacheBusters(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a generated server")
	}
	t.Parallel()
	api, srv := newFakeAPI(false)
	defer srv.Close()
	s := httpSpec()
	s.Service.BaseURL = ""
	s.Tools = []spec.Tool{{
		Name: "echo", Description: "Echo.", Enabled: true, Kind: "read",
		Request: spec.Request{Method: "GET", Path: "/api/echo", BodyType: "none",
			Query: map[string]any{"_": "{{now_ms}}", "_dc": "{{now_s}}", "r": "{{random}}", "lang": "en"}},
		Inputs: []spec.Input{},
		Source: spec.Source{Key: "GET /api/echo", Samples: 2},
	}}
	bin := buildServer(t, s)
	cs := connect(t, bin, nasEnv(srv.URL)...)
	start := time.Now()
	mustOK(t, cs, "echo", nil)
	api.mu.Lock()
	raw := api.lastQuery
	api.mu.Unlock()
	q, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	ms, err1 := strconv.ParseInt(q.Get("_"), 10, 64)
	sec, err2 := strconv.ParseInt(q.Get("_dc"), 10, 64)
	r, err3 := strconv.ParseFloat(q.Get("r"), 64)
	if err1 != nil || err2 != nil || err3 != nil || q.Get("lang") != "en" {
		t.Fatalf("query = %q", raw)
	}
	if d := time.UnixMilli(ms).Sub(start); d < -time.Minute || d > time.Minute {
		t.Errorf("_ = %d is not the current time", ms)
	}
	if d := time.Unix(sec, 0).Sub(start); d < -time.Minute || d > time.Minute {
		t.Errorf("_dc = %d is not the current time", sec)
	}
	if r < 0 || r >= 1 {
		t.Errorf("r = %v", r)
	}
}

// With no submit selector the browser login presses Enter in the password
// field, so the page's own submit handler (which scrambles the password)
// runs. The server also finds Chrome by itself.
func TestGeneratedServerBrowserLoginEnter(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a generated server with Chrome")
	}
	if findChrome() == "" {
		t.Skip("Chrome is not installed")
	}
	t.Parallel()
	_, srv := newFakeAPI(true)
	defer srv.Close()
	s := browserSpec()
	s.Service.BaseURL = ""
	s.Auth.Login.PageURL = "/#/login"
	s.Auth.Login.Form.Submit = ""
	s.Tools = s.Tools[:1]
	bin := buildServer(t, s)
	cs := connect(t, bin, nasEnv(srv.URL, "NAS_FILES_DIR="+t.TempDir())...)
	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
		t.Fatalf("list_disks = %s", text)
	}
}

// funcSource returns the printed source of a top-level function, without
// its doc comment.
func funcSource(t *testing.T, src []byte, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name {
			fd.Doc = nil
			var b strings.Builder
			if err := printer.Fprint(&b, fset, fd); err != nil {
				t.Fatal(err)
			}
			return b.String()
		}
	}
	t.Fatalf("no func %s", name)
	return ""
}

// The generated browser login looks for the same browsers in the same
// places as the recorder.
func TestBrowserCandidatesMatchRecorder(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(browserSpec(), Options{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	gen := funcSource(t, []byte(readFile(t, filepath.Join(dir, browserLoginFile))), "browserCandidates")
	rec := funcSource(t, []byte(readFile(t, filepath.Join("..", "record", "browser.go"))), "browserCandidates")
	if gen != rec {
		t.Errorf("browserCandidates differs from internal/record:\n--- generated\n%s\n--- record\n%s", gen, rec)
	}
}

// Windows directory junctions are reported as symlinks, so the sandbox
// resolves them like any other link.
func TestGeneratedMainKeepsJunctionsAsLinks(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(httpSpec(), Options{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	if main := readFile(t, filepath.Join(dir, "main.go")); !strings.Contains(main, "\n//go:debug winsymlink=0\n") {
		t.Errorf("main.go lacks //go:debug winsymlink=0:\n%s", main[:300])
	}
	if files := readFile(t, filepath.Join(dir, "files_gen.go")); !strings.Contains(files, "ModeIrregular") {
		t.Error("files_gen.go does not check for reparse points")
	}
}

// The README says how Basic auth logs in.
func TestGenerateBasicAuthReadme(t *testing.T) {
	dir := t.TempDir()
	s := &spec.Spec{Har2mcp: spec.FormatVersion, Service: spec.Service{Name: "cam"}, Auth: spec.Auth{Mode: "basic"},
		Tools: []spec.Tool{{Name: "status", Kind: "read", Enabled: true, Request: spec.Request{Method: "GET", Path: "/status"}, Inputs: []spec.Input{}}}}
	if _, err := Generate(s, Options{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	readme := readFile(t, filepath.Join(dir, "README.md"))
	for _, want := range []string{"HTTP Basic", "CAM_USER", "CAM_PASSWORD"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README lacks %q", want)
		}
	}
}
