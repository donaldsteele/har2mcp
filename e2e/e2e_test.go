// Package e2e runs the whole har2mcp pipeline against fakenas: record a
// labeled session in headless Chrome, analyze it, generate a Go MCP server,
// build it, then drive the built server with the MCP SDK's client and check
// the fake NAS's state.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/donaldsteele/har2mcp/internal/analyze"
	"github.com/donaldsteele/har2mcp/internal/fakenas"
	"github.com/donaldsteele/har2mcp/internal/generate"
	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/record"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// workDir holds every pipeline's recording, spec, generated module and
// binary. It lives for the whole test binary so tests that share a fakenas
// configuration record and build only once.
var workDir string

func TestMain(m *testing.M) {
	flag.Parse()
	dir, err := os.MkdirTemp("", "har2mcp-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	workDir = dir
	code := m.Run()
	closePipelines()
	os.RemoveAll(dir)
	os.Exit(code)
}

// built is one pipeline run: the recording, the analyzed spec, the generated
// module and the server binary built from it.
type built struct {
	recorded *fakenas.Server // the NAS the session was recorded against
	harPath  string
	specPath string
	genDir   string
	bin      string
	spec     *spec.Spec // as loaded back from specPath
}

type pipelineOnce struct {
	once sync.Once
	b    *built
	err  error
}

var (
	pipelinesMu sync.Mutex
	pipelines   = map[fakenas.Config]*pipelineOnce{}
)

func closePipelines() {
	pipelinesMu.Lock()
	defer pipelinesMu.Unlock()
	for _, p := range pipelines {
		if p.b != nil && p.b.recorded != nil {
			p.b.recorded.Close()
		}
	}
}

// requirePrereqs returns the browser the recorder uses, skipping the test when
// the end-to-end prerequisites are missing.
func requirePrereqs(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end test: records with Chrome and builds a generated server")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go command is not on PATH")
	}
	browser, err := record.FindBrowser()
	if err != nil {
		t.Skipf("no browser: %v", err)
	}
	return browser
}

// pipelineFor records, analyzes, generates and builds once per fakenas
// configuration and returns the shared result.
func pipelineFor(t *testing.T, cfg fakenas.Config) *built {
	t.Helper()
	browser := requirePrereqs(t)
	pipelinesMu.Lock()
	p := pipelines[cfg]
	if p == nil {
		p = &pipelineOnce{}
		pipelines[cfg] = p
	}
	pipelinesMu.Unlock()
	p.once.Do(func() {
		start := time.Now()
		p.b, p.err = runPipeline(cfg, browser)
		if p.err == nil {
			t.Logf("pipeline %+v built in %s", cfg, time.Since(start).Round(time.Millisecond))
		}
	})
	if p.err != nil {
		t.Fatalf("pipeline %+v: %v", cfg, p.err)
	}
	return p.b
}

// pipeline returns a fresh fakenas with cfg for this test (closed when the
// test ends) and the path of the MCP server binary that was generated from a
// recording of a fakenas with the same configuration.
func pipeline(t *testing.T, cfg fakenas.Config) (*fakenas.Server, string) {
	t.Helper()
	b := pipelineFor(t, cfg)
	srv := fakenas.Start(cfg)
	t.Cleanup(srv.Close)
	return srv, b.bin
}

// runPipeline does record → analyze → enable every tool → save and reload
// the spec → generate (with go mod tidy) → go vet → go build.
func runPipeline(cfg fakenas.Config, browser string) (*built, error) {
	dir, err := os.MkdirTemp(workDir, "pipeline-")
	if err != nil {
		return nil, err
	}
	b := &built{
		harPath:  filepath.Join(dir, "session.har"),
		specPath: filepath.Join(dir, "nas.spec.yaml"),
		genDir:   filepath.Join(dir, "nas-mcp"),
		bin:      filepath.Join(dir, "nas-mcp-server"),
	}
	if runtime.GOOS == "windows" {
		b.bin += ".exe"
	}

	// 1. Record a labeled session, as a person would through the overlay.
	srv := fakenas.Start(cfg)
	b.recorded = srv
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := record.Run(ctx, record.Options{
		URL:         srv.URL,
		Out:         b.harPath,
		BrowserPath: browser,
		Insecure:    cfg.TLS,
		Headless:    true,
		Script:      srv.Script(fakenas.ScriptOptions{DeleteAndReboot: true}),
	}); err != nil {
		return b, fmt.Errorf("record: %w", err)
	}
	if got := srv.Shares(); !slices.Equal(got, []string{"public"}) {
		return b, fmt.Errorf("after recording, shares = %v, want [public] (media added, then deleted)", got)
	}
	if !srv.Rebooted() {
		return b, fmt.Errorf("after recording, the NAS was not rebooted")
	}
	if _, ok := srv.Files()["/public/hello.txt"]; !ok {
		return b, fmt.Errorf("after recording, /public/hello.txt is missing; files = %v", slices.Sorted(maps.Keys(srv.Files())))
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(b.harPath); err != nil {
			return b, err
		} else if st.Mode().Perm() != 0o600 {
			return b, fmt.Errorf("recording mode = %v, want 0600", st.Mode().Perm())
		}
	}

	// 2. Analyze the saved recording.
	h, err := har.Load(b.harPath)
	if err != nil {
		return b, fmt.Errorf("load recording: %w", err)
	}
	s, err := analyze.Analyze([]*har.HAR{h}, analyze.Options{Name: "nas"})
	if err != nil {
		return b, fmt.Errorf("analyze: %w", err)
	}

	// 3. Full control: every tool on.
	for i := range s.Tools {
		s.Tools[i].Enabled = true
	}
	if err := spec.Save(b.specPath, s); err != nil {
		return b, fmt.Errorf("save spec: %w", err)
	}
	if b.spec, err = spec.Load(b.specPath); err != nil {
		return b, fmt.Errorf("load spec: %w", err)
	}

	// 4. Generate, with go mod tidy.
	if _, err := generate.Generate(b.spec, generate.Options{Target: "go", OutDir: b.genDir, Tidy: true}); err != nil {
		return b, fmt.Errorf("generate: %w", err)
	}

	// 5. Vet and build the generated module.
	if err := goCmd(b.genDir, "vet", "./..."); err != nil {
		return b, err
	}
	if err := goCmd(b.genDir, "build", "-o", b.bin, "."); err != nil {
		return b, err
	}
	return b, nil
}

func goCmd(dir string, args ...string) error {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return nil
}

// logBuffer collects a server's stderr and prints it if the test fails.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// connect starts the generated server binary over stdio with the env vars
// for srv and returns an MCP client session. extraEnv is appended last.
func connect(t *testing.T, bin string, srv *fakenas.Server, filesDir string, extraEnv ...string) *mcp.ClientSession {
	t.Helper()
	logs := &logBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("generated server stderr:\n%s", logs.String())
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"NAS_URL="+srv.URL,
		"NAS_USER="+fakenas.DefaultUser,
		"NAS_PASSWORD="+fakenas.DefaultPassword,
		"NAS_FILES_DIR="+filesDir,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	cmd.Stderr = logs
	client := mcp.NewClient(&mcp.Implementation{Name: "har2mcp-e2e", Version: "test"}, nil)
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect to %s: %v", bin, err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s(%v): %v", name, args, err)
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
		t.Fatalf("%s(%v) returned an error result: %s", name, args, text)
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

func listTools(t *testing.T, cs *mcp.ClientSession) map[string]*mcp.Tool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	tools := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		tools[tool.Name] = tool
	}
	return tools
}

func toolNames(tools map[string]*mcp.Tool) []string {
	return slices.Sorted(maps.Keys(tools))
}

// fileMeta is what file tools return instead of file contents.
type fileMeta struct {
	Path        string `json:"path"`
	Bytes       int64  `json:"bytes"`
	ContentType string `json:"content_type"`
}

func TestE2E_HTTPMode(t *testing.T) {
	t.Parallel()
	srv, bin := pipeline(t, fakenas.Config{})
	if mode := pipelineFor(t, fakenas.Config{}).spec.Auth.Mode; mode != "http" {
		t.Errorf("auth mode = %q, want http", mode)
	}
	cs := connect(t, bin, srv, t.TempDir())

	tools := listTools(t, cs)
	for _, name := range []string{"list_disks", "add_share", "delete_share", "reboot", "upload_file", "download_file"} {
		if tools[name] == nil {
			t.Fatalf("ListTools lacks %s; have %v", name, toolNames(tools))
		}
	}
	if a := tools["reboot"].Annotations; a == nil || a.DestructiveHint == nil || !*a.DestructiveHint || a.ReadOnlyHint {
		t.Errorf("reboot annotations = %+v, want destructive", a)
	}
	if a := tools["delete_share"].Annotations; a == nil || a.DestructiveHint == nil || !*a.DestructiveHint {
		t.Errorf("delete_share annotations = %+v, want destructive", a)
	}
	if a := tools["list_disks"].Annotations; a == nil || !a.ReadOnlyHint {
		t.Errorf("list_disks annotations = %+v, want read-only", a)
	}
	if a := tools["add_share"].Annotations; a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint {
		t.Errorf("add_share annotations = %+v, want a non-destructive change", a)
	}
	schema, _ := json.Marshal(tools["add_share"].InputSchema)
	if !strings.Contains(string(schema), `"name"`) {
		t.Errorf("add_share input schema has no name: %s", schema)
	}

	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") || !strings.Contains(text, "WD Red 4TB") {
		t.Errorf("list_disks = %s", text)
	}

	mustOK(t, cs, "add_share", map[string]any{"name": "backups"})
	if got := srv.Shares(); !slices.Equal(got, []string{"backups", "public"}) {
		t.Errorf("shares after add_share = %v, want [backups public]", got)
	}
	mustOK(t, cs, "delete_share", map[string]any{"name": "backups"})
	if got := srv.Shares(); !slices.Equal(got, []string{"public"}) {
		t.Errorf("shares after delete_share = %v, want [public]", got)
	}
	// A device error comes back as an error result, not a protocol error.
	if text := mustErr(t, cs, "delete_share", map[string]any{"name": "nope"}); !strings.Contains(text, "404") {
		t.Errorf("deleting a missing share = %s, want the 404 status", text)
	}

	if srv.Rebooted() {
		t.Fatal("a fresh NAS is already rebooted")
	}
	mustOK(t, cs, "reboot", nil)
	if !srv.Rebooted() {
		t.Error("reboot did not reboot the NAS")
	}
}

func TestE2E_FileUploadDownload(t *testing.T) {
	t.Parallel()
	srv, bin := pipeline(t, fakenas.Config{})
	filesDir := t.TempDir()
	cs := connect(t, bin, srv, filesDir)

	// Upload a local file from the files folder.
	upload := []byte("hello from the e2e test\n")
	if err := os.WriteFile(filepath.Join(filesDir, "a.txt"), upload, 0o644); err != nil {
		t.Fatal(err)
	}
	text := mustOK(t, cs, "upload_file", map[string]any{"local_path": "a.txt", "path": "/public"})
	var meta fileMeta
	if err := json.Unmarshal([]byte(text), &meta); err != nil || meta.Bytes != int64(len(upload)) || !strings.HasSuffix(meta.Path, "a.txt") {
		t.Errorf("upload_file result = %s (%v)", text, err)
	}
	if got, ok := srv.Files()["/public/a.txt"]; !ok || !bytes.Equal(got, upload) {
		t.Errorf("NAS /public/a.txt = %q (present %v), want %q", got, ok, upload)
	}

	// Download a binary file bigger than the tool result cap: it must go to
	// disk and never through the MCP message.
	data := make([]byte, 300_000)
	rand.Read(data)
	srv.PutFile("/public/b.bin", data)
	text = mustOK(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": "b.bin"})
	if len(text) > 2000 {
		t.Errorf("download_file returned %d bytes of text; file contents must not pass through MCP", len(text))
	}
	meta = fileMeta{}
	if err := json.Unmarshal([]byte(text), &meta); err != nil || meta.Bytes != int64(len(data)) || meta.ContentType == "" {
		t.Errorf("download_file result = %s (%v)", text, err)
	}
	got, err := os.ReadFile(filepath.Join(filesDir, "b.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("downloaded b.bin: %d bytes, differs from the %d bytes on the NAS", len(got), len(data))
	}
}

func TestE2E_FileSandbox(t *testing.T) {
	t.Parallel()
	srv, bin := pipeline(t, fakenas.Config{})
	filesDir := t.TempDir()
	cs := connect(t, bin, srv, filesDir)

	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("not for the NAS"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.PutFile("/public/b.bin", []byte("nas file"))
	before := srv.Files()

	// Uploads of paths outside the files folder.
	mustErr(t, cs, "upload_file", map[string]any{"local_path": "../../etc/passwd", "path": "/public"})
	mustErr(t, cs, "upload_file", map[string]any{"local_path": filepath.Join("..", filepath.Base(outside), "secret.txt"), "path": "/public"})
	mustErr(t, cs, "upload_file", map[string]any{"local_path": secret, "path": "/public"})
	// Downloads to paths outside the files folder.
	mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": "../escape.bin"})
	mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": filepath.Join(outside, "x.bin")})

	// Symlinks that point out of the files folder.
	if err := os.Symlink(secret, filepath.Join(filesDir, "link.txt")); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		t.Logf("symlink checks skipped: %v", err)
	} else {
		if err := os.Symlink(outside, filepath.Join(filesDir, "linkdir")); err != nil {
			t.Fatal(err)
		}
		mustErr(t, cs, "upload_file", map[string]any{"local_path": "link.txt", "path": "/public"})
		mustErr(t, cs, "upload_file", map[string]any{"local_path": "linkdir/secret.txt", "path": "/public"})
		mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": "linkdir/x.bin"})
		mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": "link.txt"})
	}

	// A Windows directory junction pointing out of the files folder. Any
	// user can make one (mklink /J needs no admin rights), and Go does not
	// report it as a symlink by default, so filepath.EvalSymlinks would not
	// follow it.
	if runtime.GOOS == "windows" {
		junction := filepath.Join(filesDir, "junction")
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v\n%s", err, out)
		}
		mustErr(t, cs, "upload_file", map[string]any{"local_path": `junction\secret.txt`, "path": "/public"})
		mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": `junction\x.bin`})
		mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": `junction\new\x.bin`})
		mustErr(t, cs, "download_file", map[string]any{"path": "/public/b.bin", "local_path": "junction"})
	}

	after := srv.Files()
	if !maps.EqualFunc(before, after, bytes.Equal) {
		t.Errorf("NAS files changed: before %v, after %v", slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after)))
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("files appeared outside the sandbox: %v", names)
	}
	if b, _ := os.ReadFile(secret); string(b) != "not for the NAS" {
		t.Errorf("the file outside the sandbox changed: %q", b)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(filesDir), "escape.bin")); err == nil {
		t.Error("download wrote ../escape.bin outside the files folder")
	}

	// The sandbox does not get in the way of a normal call afterwards.
	if err := os.WriteFile(filepath.Join(filesDir, "ok.txt"), []byte("fine"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustOK(t, cs, "upload_file", map[string]any{"local_path": "ok.txt", "path": "/public"})
	if got := string(srv.Files()["/public/ok.txt"]); got != "fine" {
		t.Errorf("NAS /public/ok.txt = %q", got)
	}
}

func TestE2E_SessionExpiryRelogin(t *testing.T) {
	t.Parallel()
	srv, bin := pipeline(t, fakenas.Config{})
	cs := connect(t, bin, srv, t.TempDir())

	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
		t.Fatalf("list_disks = %s", text)
	}
	srv.ExpireSessions()
	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
		t.Errorf("list_disks after the session expired = %s", text)
	}
	// A change after a second expiry also logs in again and goes through.
	srv.ExpireSessions()
	mustOK(t, cs, "add_share", map[string]any{"name": "after_expiry"})
	if got := srv.Shares(); !slices.Contains(got, "after_expiry") {
		t.Errorf("shares = %v, want after_expiry added", got)
	}
}

func TestE2E_BadPassword(t *testing.T) {
	t.Parallel()
	srv, bin := pipeline(t, fakenas.Config{})
	cs := connect(t, bin, srv, t.TempDir(), "NAS_PASSWORD=wrong")
	if text := mustErr(t, cs, "list_disks", nil); !strings.Contains(strings.ToLower(text), "login") {
		t.Errorf("list_disks with a wrong password = %s, want a login error", text)
	}
}

func TestE2E_BrowserMode(t *testing.T) {
	t.Parallel()
	cfg := fakenas.Config{Scramble: true}
	srv, bin := pipeline(t, cfg)
	s := pipelineFor(t, cfg).spec
	if s.Auth.Mode != "browser" {
		t.Fatalf("auth mode = %q, want browser", s.Auth.Mode)
	}
	if s.Auth.Login == nil || s.Auth.Login.Form == nil || s.Auth.Login.Form.Password != "#password" {
		t.Fatalf("login = %+v, want the recorded form selectors", s.Auth.Login)
	}
	browser, _ := record.FindBrowser()
	cs := connect(t, bin, srv, t.TempDir(), "NAS_BROWSER="+browser)
	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
		t.Errorf("list_disks = %s", text)
	}
	mustOK(t, cs, "add_share", map[string]any{"name": "scrambled"})
	if got := srv.Shares(); !slices.Contains(got, "scrambled") {
		t.Errorf("shares = %v, want scrambled added", got)
	}
	srv.ExpireSessions()
	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
		t.Errorf("list_disks after the session expired = %s", text)
	}
}

func TestE2E_TLSInsecure(t *testing.T) {
	t.Parallel()
	cfg := fakenas.Config{TLS: true}
	srv, bin := pipeline(t, cfg)
	if !strings.HasPrefix(srv.URL, "https://") {
		t.Fatalf("fakenas URL = %s, want https", srv.URL)
	}
	cs := connect(t, bin, srv, t.TempDir(), "NAS_INSECURE=1")
	if text := mustOK(t, cs, "list_disks", nil); !strings.Contains(text, "sda") {
		t.Errorf("list_disks over self-signed TLS = %s", text)
	}
	// Without NAS_INSECURE the self-signed certificate is refused.
	strict := connect(t, bin, srv, t.TempDir())
	if text := mustErr(t, strict, "list_disks", nil); !strings.Contains(text, "certificate") {
		t.Errorf("list_disks without NAS_INSECURE = %s, want a certificate error", text)
	}
}

// TestE2E_NoSecrets checks the anti-goal: the spec and the generated code
// never contain the recorded password, session cookie or CSRF token.
func TestE2E_NoSecrets(t *testing.T) {
	t.Parallel()
	for _, cfg := range []fakenas.Config{{}, {Scramble: true}} {
		b := pipelineFor(t, cfg)
		secrets := recordedSecrets(t, b.harPath)
		if len(secrets) < 3 {
			t.Fatalf("%+v: found only %d secrets in the recording (%v); want the password, a cookie and a token", cfg, len(secrets), secrets)
		}
		files := []string{b.specPath}
		err := filepath.WalkDir(b.genDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && d.Name() != "go.sum" {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range secrets {
				if bytes.Contains(data, []byte(secret)) {
					t.Errorf("%+v: %s contains the recorded secret %q", cfg, f, secret)
				}
			}
		}
	}
}

// recordedSecrets returns the password, session cookie values and CSRF
// tokens found in a recording.
func recordedSecrets(t *testing.T, harPath string) []string {
	t.Helper()
	h, err := har.Load(harPath)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{fakenas.DefaultPassword: true}
	if h.Log.Har2mcp != nil && h.Log.Har2mcp.Login != nil && h.Log.Har2mcp.Login.Password != "" {
		seen[h.Log.Har2mcp.Login.Password] = true
	}
	for _, e := range h.Log.Entries {
		for _, c := range e.Response.Cookies {
			if c.Name == "NASSESSID" && c.Value != "" {
				seen[c.Value] = true
			}
		}
		for _, hd := range e.Response.Headers {
			if strings.EqualFold(hd.Name, "Set-Cookie") {
				if v, ok := strings.CutPrefix(hd.Value, "NASSESSID="); ok {
					v, _, _ = strings.Cut(v, ";")
					if v != "" {
						seen[v] = true
					}
				}
			}
		}
		if strings.HasSuffix(e.Request.URL, "/api/login") && e.Response.Status == 200 {
			body, err := e.Response.Content.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			var resp struct {
				Data struct {
					Token string `json:"token"`
				} `json:"data"`
			}
			if json.Unmarshal(body, &resp) == nil && resp.Data.Token != "" {
				seen[resp.Data.Token] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

var (
	cliOnce sync.Once
	cliBin  string
	cliErr  error
)

// har2mcpBinary builds the har2mcp command once per test run.
func har2mcpBinary(t *testing.T) string {
	t.Helper()
	cliOnce.Do(func() {
		cliBin = filepath.Join(workDir, "har2mcp")
		if runtime.GOOS == "windows" {
			cliBin += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", cliBin, "../cmd/har2mcp")
		if out, err := cmd.CombinedOutput(); err != nil {
			cliErr = fmt.Errorf("go build ./cmd/har2mcp: %v\n%s", err, out)
		}
	})
	if cliErr != nil {
		t.Fatal(cliErr)
	}
	return cliBin
}

// cli runs har2mcp in dir and returns its combined output and exit code.
func cli(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(har2mcpBinary(t), args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "ANTHROPIC_API_KEY=")
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("har2mcp %s: %v", strings.Join(args, " "), err)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

func cliOK(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, code := cli(t, dir, args...)
	if code != 0 {
		t.Fatalf("har2mcp %s exited %d:\n%s", strings.Join(args, " "), code, out)
	}
	if strings.Contains(out, fakenas.DefaultPassword) {
		t.Errorf("har2mcp %s printed the password:\n%s", strings.Join(args, " "), out)
	}
	return out
}

// TestE2E_CLI drives the har2mcp command itself over a real recording:
// inspect, analyze (and a merge that keeps a hand edit), redact, enhance
// --dry-run, generate, then builds and starts the generated server.
func TestE2E_CLI(t *testing.T) {
	t.Parallel()
	b := pipelineFor(t, fakenas.Config{})
	dir := t.TempDir()
	rec, err := os.ReadFile(b.harPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nas.har"), rec, 0o600); err != nil {
		t.Fatal(err)
	}

	if out := cliOK(t, dir, "version"); !strings.HasPrefix(out, "har2mcp ") {
		t.Errorf("version = %q", out)
	}
	if out, code := cli(t, dir, "analyze"); code != 2 {
		t.Errorf("analyze with no file exited %d, want 2 (usage):\n%s", code, out)
	}

	out := cliOK(t, dir, "inspect", "nas.har", "--name", "nas")
	for _, want := range []string{"Auth: http", "list_disks", "upload_file", "NASSESSID"} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect nas.har lacks %q:\n%s", want, out)
		}
	}

	out = cliOK(t, dir, "analyze", "nas.har", "--name", "nas")
	if !strings.Contains(out, "har2mcp generate nas.spec.yaml") {
		t.Errorf("analyze does not print the next command:\n%s", out)
	}
	specPath := filepath.Join(dir, "nas.spec.yaml")
	if _, err := spec.Load(specPath); err != nil {
		t.Fatalf("analyze wrote an invalid spec: %v", err)
	}
	cliOK(t, dir, "inspect", "nas.spec.yaml")

	// A hand edit survives a second analyze, which merges into the spec.
	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), "name: list_disks\n", "name: get_disks\n", 1)
	if edited == string(data) {
		t.Fatalf("spec has no list_disks tool:\n%s", data)
	}
	if err := os.WriteFile(specPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	cliOK(t, dir, "analyze", "nas.har", "--name", "nas")
	merged, err := spec.Load(specPath)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range merged.Tools {
		names[tool.Name] = true
	}
	if !names["get_disks"] || names["list_disks"] {
		t.Errorf("after re-analyze, tools = %v; want the hand rename get_disks kept", slices.Sorted(maps.Keys(names)))
	}

	cliOK(t, dir, "redact", "nas.har", "-o", "redacted.har")
	if red, err := os.ReadFile(filepath.Join(dir, "redacted.har")); err != nil || bytes.Contains(red, []byte(fakenas.DefaultPassword)) {
		t.Errorf("redacted.har: %v, has password %v", err, bytes.Contains(red, []byte(fakenas.DefaultPassword)))
	}
	if out, code := cli(t, dir, "redact", "nas.har", "-o", "nas.har"); code == 0 {
		t.Errorf("redact onto its input succeeded:\n%s", out)
	}

	before, _ := os.ReadFile(specPath)
	out = cliOK(t, dir, "enhance", "nas.spec.yaml", "--dry-run")
	if !strings.Contains(out, "get_disks") {
		t.Errorf("enhance --dry-run does not show the tools:\n%s", out)
	}
	if after, _ := os.ReadFile(specPath); !bytes.Equal(before, after) {
		t.Error("enhance --dry-run changed the spec")
	}
	if out, code := cli(t, dir, "enhance", "nas.spec.yaml"); code != 1 || !strings.Contains(out, "ANTHROPIC_API_KEY") {
		t.Errorf("enhance without a key exited %d:\n%s", code, out)
	}

	out = cliOK(t, dir, "generate", "nas.spec.yaml", "--target", "go", "-o", "nas-mcp")
	if !strings.Contains(out, "claude mcp add") {
		t.Errorf("generate does not print the registration command:\n%s", out)
	}
	genDir := filepath.Join(dir, "nas-mcp")
	bin := filepath.Join(dir, "nas-mcp-bin")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if err := goCmd(genDir, "build", "-o", bin, "."); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "--version").CombinedOutput(); err != nil || !strings.Contains(string(out), "nas-mcp") {
		t.Errorf("generated server --version: %v\n%s", err, out)
	}
	srv := fakenas.Start(fakenas.Config{})
	t.Cleanup(srv.Close)
	cs := connect(t, bin, srv, t.TempDir())
	if text := mustOK(t, cs, "get_disks", nil); !strings.Contains(text, "sda") {
		t.Errorf("get_disks = %s", text)
	}
}
