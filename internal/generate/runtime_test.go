package generate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/donaldsteele/har2mcp/internal/spec"
)

// fakeAPI is a small TOS-style device API for driving generated servers:
// JSON login that sets a session cookie and returns a CSRF token, an RPC
// endpoint with an act field, multipart upload and attachment download.
// With scramble set, the login page hashes the password in the browser.
type fakeAPI struct {
	user, password string
	scramble       bool

	mu        sync.Mutex
	sessions  map[string]string // session id -> csrf token
	nonces    map[string]bool
	logins    int
	shares    []string
	files     map[string][]byte
	downloads int
	lastBody  map[string]any
	lastQuery string
	lastPath  string
}

func newFakeAPI(scramble bool) (*fakeAPI, *httptest.Server) {
	f := &fakeAPI{
		user: "admin", password: "hunter2-nas", scramble: scramble,
		sessions: map[string]string{}, nonces: map[string]bool{},
		shares: []string{"public"}, files: map[string][]byte{},
	}
	srv := httptest.NewServer(f)
	return f, srv
}

func randHex() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (f *fakeAPI) expire() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions = map[string]string{}
}

func (f *fakeAPI) stats() (logins, downloads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins, f.downloads
}

// authorized checks the session cookie and the CSRF header.
func (f *fakeAPI) authorized(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie("NASSESSID")
	f.mu.Lock()
	token, ok := "", false
	if err == nil {
		token, ok = f.sessions[c.Value]
	}
	f.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "not logged in"})
		return false
	}
	if r.Header.Get("X-Csrf-Token") != token {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "bad token"})
		return false
	}
	return true
}

const loginPage = `<!doctype html><html><body>
<form id="f"><input id="username"><input id="password" type="password"><button id="login" type="submit">Log in</button></form>
<pre id="out"></pre>
<script>
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const user = document.getElementById('username').value;
  let pw = document.getElementById('password').value;
  const n = await (await fetch('/api/nonce')).json();
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw + ':' + n.nonce));
  pw = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  const r = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: user, password: pw, nonce: n.nonce})});
  document.getElementById('out').textContent = await r.text();
});
</script></body></html>`

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/":
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, loginPage)
	case r.URL.Path == "/api/nonce":
		n := randHex()
		f.mu.Lock()
		f.nonces[n] = true
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"nonce": n})
	case r.URL.Path == "/api/login":
		var in struct{ Username, Password, Nonce string }
		json.NewDecoder(r.Body).Decode(&in)
		want := f.password
		if f.scramble {
			f.mu.Lock()
			okNonce := f.nonces[in.Nonce]
			delete(f.nonces, in.Nonce)
			f.mu.Unlock()
			sum := sha256.Sum256([]byte(f.password + ":" + in.Nonce))
			want = hex.EncodeToString(sum[:])
			if !okNonce {
				want = "\x00no nonce"
			}
		}
		if in.Username != f.user || in.Password != want {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "bad credentials"})
			return
		}
		id, token := randHex(), randHex()
		f.mu.Lock()
		f.sessions[id] = token
		f.logins++
		f.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "NASSESSID", Value: id, Path: "/", HttpOnly: true})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"token": token}})
	case r.URL.Path == "/api.php":
		if !f.authorized(w, r) {
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json"})
			return
		}
		f.mu.Lock()
		f.lastBody, f.lastQuery = body, r.URL.RawQuery
		f.mu.Unlock()
		name, _ := body["name"].(string)
		switch body["act"] {
		case "getdisklist":
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": []any{
				map[string]any{"id": "sda", "model": "WD Red 4TB"}, map[string]any{"id": "sdb", "model": "WD Red 4TB"}}})
		case "addshare":
			if name == "" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "name required"})
				return
			}
			f.mu.Lock()
			f.shares = append(f.shares, name)
			f.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		case "delshare":
			f.mu.Lock()
			var keep []string
			for _, s := range f.shares {
				if s != name {
					keep = append(keep, s)
				}
			}
			f.shares = keep
			f.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		case "setopts", "reboot":
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		default:
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "unknown act"})
		}
	case strings.HasPrefix(r.URL.Path, "/api/v1/disks/"):
		if !f.authorized(w, r) {
			return
		}
		f.mu.Lock()
		f.lastPath = r.URL.Path
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": path.Base(r.URL.Path)})
	case r.URL.Path == "/api/big":
		if !f.authorized(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, strings.Repeat("0123456789", 15000))
	case r.URL.Path == "/api/upload":
		if !f.authorized(w, r) {
			return
		}
		if r.ContentLength <= 0 {
			writeJSON(w, http.StatusLengthRequired, map[string]any{"ok": false, "error": "length required"})
			return
		}
		file, hdr, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		defer file.Close()
		data, _ := io.ReadAll(file)
		f.mu.Lock()
		f.files[path.Join(r.FormValue("path"), hdr.Filename)] = data
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case r.URL.Path == "/api/download":
		if !f.authorized(w, r) {
			return
		}
		p := r.URL.Query().Get("path")
		f.mu.Lock()
		data, ok := f.files[p]
		f.downloads++
		f.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "no such file"})
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(p)))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

// buildServer generates s into a temp dir, builds it, and returns the binary.
func buildServer(t *testing.T, s *spec.Spec) string {
	t.Helper()
	dir := generateAndBuild(t, s)
	bin := filepath.Join(dir, "server")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	goCmd(t, dir, "build", "-o", bin, ".")
	return bin
}

// connect starts bin as an MCP server with env and returns a client session.
func connect(t *testing.T, bin string, env ...string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = &testWriter{t: t}
	client := mcp.NewClient(&mcp.Implementation{Name: "har2mcp-test", Version: "test"}, nil)
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Logf("server: %s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

func mustOK(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	text, isErr := callTool(t, cs, name, args)
	if isErr {
		t.Fatalf("%s returned an error result: %s", name, text)
	}
	return text
}

func mustErr(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	text, isErr := callTool(t, cs, name, args)
	if !isErr {
		t.Fatalf("%s(%v) succeeded, want an error result: %s", name, args, text)
	}
	return text
}

func TestGeneratedServerHTTPMode(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a generated server")
	}
	t.Parallel()
	api, srv := newFakeAPI(false)
	defer srv.Close()
	s := httpSpec()
	s.Service.BaseURL = "" // the URL comes from NAS_URL
	bin := buildServer(t, s)

	filesDir := t.TempDir()
	cs := connect(t, bin, "NAS_URL="+srv.URL, "NAS_USER=admin", "NAS_PASSWORD=hunter2-nas", "NAS_FILES_DIR="+filesDir)

	ctx := context.Background()
	lt, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*mcp.Tool{}
	for _, tool := range lt.Tools {
		byName[tool.Name] = tool
	}
	for _, name := range []string{"list_disks", "add_share", "delete_share", "reboot", "get_disk", "set_options", "upload_file", "download_file"} {
		if byName[name] == nil {
			t.Fatalf("ListTools lacks %s; have %v", name, keys(byName))
		}
	}
	if a := byName["reboot"].Annotations; a == nil || a.DestructiveHint == nil || !*a.DestructiveHint || a.ReadOnlyHint {
		t.Errorf("reboot annotations = %+v, want destructive", a)
	}
	if a := byName["list_disks"].Annotations; a == nil || !a.ReadOnlyHint {
		t.Errorf("list_disks annotations = %+v, want read-only", a)
	}
	if a := byName["add_share"].Annotations; a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint {
		t.Errorf("add_share annotations = %+v, want a non-destructive change", a)
	}
	schema, _ := json.Marshal(byName["add_share"].InputSchema)
	if !strings.Contains(string(schema), `"required":["name"]`) || !strings.Contains(string(schema), "Share name.") {
		t.Errorf("add_share schema = %s", schema)
	}
	if !strings.Contains(byName["upload_file"].Description, "NAS_FILES_DIR") {
		t.Errorf("upload_file description does not explain local paths: %q", byName["upload_file"].Description)
	}

	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
		t.Errorf("list_disks = %s", text)
	}
	mustOK(t, cs, "add_share", map[string]any{"name": "backups"})
	api.mu.Lock()
	shares := strings.Join(api.shares, ",")
	api.mu.Unlock()
	if shares != "public,backups" {
		t.Errorf("shares after add = %s", shares)
	}
	mustOK(t, cs, "delete_share", map[string]any{"name": "backups"})
	api.mu.Lock()
	shares = strings.Join(api.shares, ",")
	api.mu.Unlock()
	if shares != "public" {
		t.Errorf("shares after delete = %s", shares)
	}

	// A device error comes back as an error result with the status.
	if text := mustErr(t, cs, "add_share", map[string]any{"name": ""}); !strings.Contains(text, "400") || !strings.Contains(text, "name required") {
		t.Errorf("error result = %s", text)
	}
	// The schema rejects a missing required input.
	mustErr(t, cs, "add_share", map[string]any{})

	if text := mustOK(t, cs, "get_disk", map[string]any{"id": 7}); !strings.Contains(text, `"7"`) {
		t.Errorf("get_disk = %s", text)
	}
	api.mu.Lock()
	lastPath := api.lastPath
	api.mu.Unlock()
	if lastPath != "/api/v1/disks/7" {
		t.Errorf("path = %s", lastPath)
	}

	// Optional inputs: given ones are merged into the fixed body at their
	// dotted paths; missing ones leave the fixed values alone.
	mustOK(t, cs, "set_options", map[string]any{"verbose": true, "limit": 5, "tags": []any{"a", "b"}})
	api.mu.Lock()
	body, query := api.lastBody, api.lastQuery
	api.mu.Unlock()
	opts, _ := body["opts"].(map[string]any)
	if body["act"] != "setopts" || opts["lang"] != "en" || opts["verbose"] != true || opts["ratio"] != 0.5 || opts["big"] != 5e9 {
		t.Errorf("set_options body = %v", body)
	}
	if fmt.Sprint(body["tags"]) != "[a b]" || body["extra"] != nil {
		t.Errorf("set_options body = %v", body)
	}
	if query != "limit=5&v=2" {
		t.Errorf("set_options query = %q", query)
	}

	// Large responses are truncated with a note.
	big := mustOK(t, cs, "big_report", nil)
	if !strings.HasSuffix(big, "[truncated: 150000 bytes total]") || len(big) > 100100 {
		t.Errorf("big_report: %d bytes, ends %q", len(big), big[len(big)-40:])
	}

	// Upload and download stay inside the files folder.
	if err := os.WriteFile(filepath.Join(filesDir, "a.txt"), []byte("hello nas"), 0o644); err != nil {
		t.Fatal(err)
	}
	up := mustOK(t, cs, "upload_file", map[string]any{"local_path": "a.txt", "path": "/public"})
	var meta struct {
		Path        string `json:"path"`
		Bytes       int64  `json:"bytes"`
		ContentType string `json:"content_type"`
	}
	if err := json.Unmarshal([]byte(up), &meta); err != nil || meta.Bytes != 9 || meta.ContentType == "" || !strings.HasSuffix(meta.Path, "a.txt") {
		t.Errorf("upload result = %s (%v)", up, err)
	}
	// .json is in Go's built-in MIME table on every OS (.txt is not).
	if err := os.WriteFile(filepath.Join(filesDir, "c.json"), []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if up := mustOK(t, cs, "upload_file", map[string]any{"local_path": "c.json", "path": "/public"}); !strings.Contains(up, `"content_type":"application/json"`) {
		t.Errorf("upload c.json = %s", up)
	}
	api.mu.Lock()
	got := string(api.files["/public/a.txt"])
	api.files["/public/b.bin"] = []byte{0, 1, 2, 3, 250}
	api.mu.Unlock()
	if got != "hello nas" {
		t.Errorf("uploaded = %q", got)
	}
	down := mustOK(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": "b.bin"})
	if strings.Contains(down, "\x00") || !strings.Contains(down, `"bytes":5`) {
		t.Errorf("download result = %q", down)
	}
	if b, err := os.ReadFile(filepath.Join(filesDir, "b.bin")); err != nil || string(b) != "\x00\x01\x02\x03\xfa" {
		t.Errorf("downloaded = %v %v", b, err)
	}
	if err := os.Mkdir(filepath.Join(filesDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustOK(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": "sub"})
	if _, err := os.Stat(filepath.Join(filesDir, "sub", "b.bin")); err != nil {
		t.Errorf("download into a folder: %v", err)
	}
	mustOK(t, cs, "download_file", map[string]any{"path": "/public/a.txt", "local_path": "new/dir/a.txt"})
	if b, _ := os.ReadFile(filepath.Join(filesDir, "new", "dir", "a.txt")); string(b) != "hello nas" {
		t.Errorf("download into new folders = %q", b)
	}
	mustOK(t, cs, "download_file", map[string]any{"path": "/public/a.txt"})
	if b, _ := os.ReadFile(filepath.Join(filesDir, "a.txt")); string(b) != "hello nas" {
		t.Errorf("download with no local path = %q", b)
	}
	if text := mustErr(t, cs, "download_file", map[string]any{"path": "/nope", "local_path": "nope.bin"}); !strings.Contains(text, "404") {
		t.Errorf("missing download = %s", text)
	}
	if _, err := os.Stat(filepath.Join(filesDir, "nope.bin")); !os.IsNotExist(err) {
		t.Error("failed download left a file")
	}

	// Sandbox escapes fail and touch nothing.
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	os.WriteFile(secret, []byte("top secret"), 0o644)
	api.mu.Lock()
	before := len(api.files)
	api.mu.Unlock()
	_, downloadsBefore := api.stats()
	mustErr(t, cs, "upload_file", map[string]any{"local_path": "../../etc/passwd", "path": "/public"})
	mustErr(t, cs, "upload_file", map[string]any{"local_path": secret, "path": "/public"})
	mustErr(t, cs, "upload_file", map[string]any{"local_path": "missing.txt", "path": "/public"})
	mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": "../escape.bin"})
	mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": filepath.Join(outside, "x.bin")})
	if runtime.GOOS != "windows" {
		if err := os.Symlink(secret, filepath.Join(filesDir, "link.txt")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(filesDir, "linkdir")); err != nil {
			t.Fatal(err)
		}
		mustErr(t, cs, "upload_file", map[string]any{"local_path": "link.txt", "path": "/public"})
		mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": "linkdir/x.bin"})
		mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": "linkdir/new/x.bin"})
		mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": "link.txt"})
	}
	api.mu.Lock()
	after := len(api.files)
	api.mu.Unlock()
	if _, d := api.stats(); d != downloadsBefore {
		t.Errorf("sandboxed downloads reached the device (%d requests)", d-downloadsBefore)
	}
	if after != before {
		t.Errorf("sandboxed uploads reached the device: %d files, want %d", after, before)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 1 {
		t.Errorf("files appeared outside the sandbox: %v", entries)
	}
	if b, _ := os.ReadFile(secret); string(b) != "top secret" {
		t.Error("secret file changed")
	}

	// An expired session logs in again and retries once.
	loginsBefore, _ := api.stats()
	api.expire()
	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
		t.Errorf("list_disks after expiry = %s", text)
	}
	if n, _ := api.stats(); n != loginsBefore+1 {
		t.Errorf("logins = %d, want %d", n, loginsBefore+1)
	}
}

func TestGeneratedServerBadPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a generated server")
	}
	t.Parallel()
	_, srv := newFakeAPI(false)
	defer srv.Close()
	s := httpSpec()
	s.Tools = s.Tools[:1]
	bin := buildServer(t, s)
	cs := connect(t, bin, "NAS_URL="+srv.URL, "NAS_USER=admin", "NAS_PASSWORD=wrong", "NAS_FILES_DIR="+t.TempDir())
	if text := mustErr(t, cs, "list_disks", nil); !strings.Contains(text, "login") || !strings.Contains(text, "401") {
		t.Errorf("bad password result = %s", text)
	}
}

func TestGeneratedServerTLSInsecure(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a generated server")
	}
	t.Parallel()
	api := &fakeAPI{user: "admin", password: "hunter2-nas", sessions: map[string]string{}, nonces: map[string]bool{}, files: map[string][]byte{}}
	srv := httptest.NewTLSServer(api)
	defer srv.Close()
	s := httpSpec()
	s.Tools = s.Tools[:1]
	bin := buildServer(t, s)
	cs := connect(t, bin, "NAS_URL="+srv.URL, "NAS_USER=admin", "NAS_PASSWORD=hunter2-nas", "NAS_INSECURE=1", "NAS_FILES_DIR="+t.TempDir())
	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
		t.Errorf("list_disks over TLS = %s", text)
	}
	strict := connect(t, bin, "NAS_URL="+srv.URL, "NAS_USER=admin", "NAS_PASSWORD=hunter2-nas", "NAS_FILES_DIR="+t.TempDir())
	if text := mustErr(t, strict, "list_disks", nil); !strings.Contains(text, "certificate") {
		t.Errorf("self-signed certificate without NAS_INSECURE = %s", text)
	}
}

// findChrome returns a Chrome or Chromium binary, or "".
func findChrome() string {
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func TestGeneratedServerBrowserMode(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a generated server with Chrome")
	}
	chrome := findChrome()
	if chrome == "" {
		t.Skip("Chrome is not installed")
	}
	t.Parallel()
	api, srv := newFakeAPI(true)
	defer srv.Close()
	s := browserSpec()
	s.Service.BaseURL = ""
	s.Auth.Login.PageURL = "http://192.168.1.10:8181/" // rebased onto NAS_URL at run time
	s.Tools = s.Tools[:2]
	bin := buildServer(t, s)
	cs := connect(t, bin, "NAS_URL="+srv.URL, "NAS_USER=admin", "NAS_PASSWORD=hunter2-nas", "NAS_FILES_DIR="+t.TempDir(), "NAS_BROWSER="+chrome)
	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
		t.Errorf("list_disks = %s", text)
	}
	mustOK(t, cs, "add_share", map[string]any{"name": "media"})
	api.expire()
	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
		t.Errorf("list_disks after expiry = %s", text)
	}
	if n, _ := api.stats(); n != 2 {
		t.Errorf("logins = %d, want 2", n)
	}

	bad := connect(t, bin, "NAS_URL="+srv.URL, "NAS_USER=admin", "NAS_PASSWORD=wrong", "NAS_FILES_DIR="+t.TempDir(), "NAS_BROWSER="+chrome)
	if text := mustErr(t, bad, "list_disks", nil); !strings.Contains(text, "login") {
		t.Errorf("bad password in browser mode = %s", text)
	}
}

func keys(m map[string]*mcp.Tool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
