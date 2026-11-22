package generate

import (
	"bufio"
	"bytes"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/donaldsteele/har2mcp/internal/spec"
)

// httpSpec is an http-mode spec modeled on a TOS-style NAS: an RPC endpoint
// with an act field, a path-parameter tool, optional inputs of every type,
// and upload and download tools.
func httpSpec() *spec.Spec {
	return &spec.Spec{
		Har2mcp: spec.FormatVersion,
		Service: spec.Service{Name: "nas", BaseURL: "http://192.168.1.10:8181", Hosts: []string{"192.168.1.10:8181"}},
		Auth: spec.Auth{
			Mode: "http",
			Login: &spec.Login{
				PageURL: "http://192.168.1.10:8181/",
				Request: spec.Request{
					Method:   "POST",
					Path:     "/api/login",
					BodyType: "json",
					Body:     map[string]any{"username": "{{username}}", "password": "{{password}}"},
				},
			},
			Session: spec.Session{
				Cookies: []string{"NASSESSID"},
				Tokens: []spec.TokenFlow{{
					Name: "csrf",
					From: spec.TokenRef{ResponseJSON: "data.token"},
					To:   spec.TokenRef{Header: "X-Csrf-Token"},
				}},
			},
			ReloginOn:           []int{401, 403},
			ReloginBodyContains: "not logged in",
		},
		Tools: []spec.Tool{
			{
				Name: "list_disks", Description: "List disks with model, size and health.", Enabled: true, Kind: "read",
				Request: spec.Request{Method: "POST", Path: "/api.php", BodyType: "json", Body: map[string]any{"act": "getdisklist"}, Discriminator: "act",
					Headers: map[string]string{"X-Requested-With": "XMLHttpRequest", "Cookie": "REDACTED", "Accept-Encoding": "gzip"}},
				Inputs:   []spec.Input{},
				Response: spec.Response{ContentType: "application/json", Example: map[string]any{"ok": true, "data": []any{map[string]any{"id": "sda"}}}},
				Source:   spec.Source{Key: "POST /api.php act=getdisklist", Steps: []string{"list disks"}, Samples: 2},
			},
			{
				Name: "add_share", Description: "Add a share.", Enabled: true, Kind: "change",
				Request: spec.Request{Method: "POST", Path: "/api.php", BodyType: "json", Body: map[string]any{"act": "addshare"}, Discriminator: "act"},
				Inputs:  []spec.Input{{Name: "name", Type: "string", Description: "Share name.", Required: true, In: "body", Field: "name", Example: "media"}},
				Source:  spec.Source{Key: "POST /api.php act=addshare", Samples: 1},
			},
			{
				Name: "delete_share", Description: "Delete a share.", Enabled: true, Kind: "destructive",
				Request: spec.Request{Method: "POST", Path: "/api.php", BodyType: "json", Body: map[string]any{"act": "delshare"}, Discriminator: "act"},
				Inputs:  []spec.Input{{Name: "name", Type: "string", Required: true, In: "body", Field: "name"}},
				Source:  spec.Source{Key: "POST /api.php act=delshare", Samples: 1},
			},
			{
				Name: "reboot", Description: "Reboot the NAS.", Enabled: true, Kind: "destructive",
				Request: spec.Request{Method: "POST", Path: "/api.php", BodyType: "json", Body: map[string]any{"act": "reboot"}, Discriminator: "act"},
				Inputs:  []spec.Input{},
				Source:  spec.Source{Key: "POST /api.php act=reboot", Samples: 1},
			},
			{
				Name: "get_disk", Description: "Get one disk.", Enabled: true, Kind: "read",
				Request: spec.Request{Method: "GET", Path: "/api/v1/disks/{id}", BodyType: "none"},
				Inputs:  []spec.Input{{Name: "id", Type: "integer", Required: true, In: "path", Field: "id"}},
				Source:  spec.Source{Key: "GET /api/v1/disks/{id}", Samples: 2},
			},
			{
				Name: "set_options", Description: "Set options.", Enabled: true, Kind: "change",
				Request: spec.Request{Method: "POST", Path: "/api.php", BodyType: "json",
					Query: map[string]any{"v": 2},
					Body:  map[string]any{"act": "setopts", "opts": map[string]any{"lang": "en", "big": int64(5000000000), "ratio": 0.5}}, Discriminator: "act"},
				Inputs: []spec.Input{
					{Name: "verbose", Type: "boolean", In: "body", Field: "opts.verbose"},
					{Name: "limit", Type: "integer", In: "query", Field: "limit"},
					{Name: "ratio", Type: "number", In: "body", Field: "opts.ratio"},
					{Name: "tags", Type: "array", In: "body", Field: "tags"},
					{Name: "extra", Type: "object", In: "body", Field: "extra"},
				},
				Source: spec.Source{Key: "POST /api.php act=setopts", Samples: 3},
			},
			{
				Name: "big_report", Description: "A large response.", Enabled: true, Kind: "read",
				Request: spec.Request{Method: "GET", Path: "/api/big", BodyType: "none"},
				Inputs:  []spec.Input{},
				Source:  spec.Source{Key: "GET /api/big", Samples: 1},
			},
			{
				Name: "upload_file", Description: "Upload a file to a NAS folder.", Enabled: true, Kind: "change",
				Request: spec.Request{Method: "POST", Path: "/api/upload", BodyType: "multipart"},
				File:    &spec.FileOp{Direction: "upload", Part: "file"},
				Inputs: []spec.Input{
					{Name: "local_path", Type: "string", Required: true, In: "file"},
					{Name: "path", Type: "string", Required: true, In: "body", Field: "path", Description: "NAS folder."},
				},
				Source: spec.Source{Key: "POST /api/upload", Samples: 1},
			},
			{
				Name: "download_file", Description: "Download a file from the NAS.", Enabled: true, Kind: "read",
				Request: spec.Request{Method: "GET", Path: "/api/download", BodyType: "none"},
				File:    &spec.FileOp{Direction: "download"},
				Inputs: []spec.Input{
					{Name: "path", Type: "string", Required: true, In: "query", Field: "path"},
					{Name: "local_path", Type: "string", In: "file"},
				},
				Source: spec.Source{Key: "GET /api/download", Samples: 1},
			},
		},
	}
}

// browserSpec is httpSpec with a browser-mode login.
func browserSpec() *spec.Spec {
	s := httpSpec()
	s.Auth.Mode = "browser"
	s.Auth.Login.Form = &spec.LoginForm{Username: "#username", Password: "#password", Submit: "#login"}
	s.Auth.Login.Request.Body = map[string]any{"username": "{{username}}", "password": "REDACTED", "nonce": "REDACTED"}
	return s
}

func requireGo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH")
	}
}

// goCmd runs the go command in dir and fails the test with its output on
// error.
func goCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
}

// generateAndBuild generates s with Tidy into a temp dir, then runs go vet
// and go build there.
func generateAndBuild(t *testing.T, s *spec.Spec) string {
	t.Helper()
	requireGo(t)
	dir := t.TempDir()
	if _, err := Generate(s, Options{Target: "go", OutDir: dir, Tidy: true}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	goCmd(t, dir, "vet", "./...")
	goCmd(t, dir, "build", "./...")
	return dir
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestVersionsMatchGoMod(t *testing.T) {
	f, err := os.Open("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "require "))
		if len(fields) >= 2 {
			got[fields[0]] = fields[1]
		}
	}
	for mod, want := range map[string]string{
		"github.com/modelcontextprotocol/go-sdk": MCPSDKVersion,
		"github.com/chromedp/chromedp":           ChromedpVersion,
		"github.com/chromedp/cdproto":            CdprotoVersion,
	} {
		if got[mod] != want {
			t.Errorf("%s: go.mod has %q, versions.go has %q", mod, got[mod], want)
		}
	}
}

func TestGenerateHTTPModeCompiles(t *testing.T) {
	t.Parallel()
	dir := generateAndBuild(t, httpSpec())
	for _, name := range []string{"go.mod", "go.sum", "main.go", "client_gen.go", "files_gen.go", "tools_gen.go", "custom.go", "README.md"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "browserlogin_gen.go")); err == nil {
		t.Error("http mode wrote browserlogin_gen.go")
	}
	if gomod := readFile(t, filepath.Join(dir, "go.mod")); strings.Contains(gomod, "chromedp") {
		t.Errorf("http-mode go.mod requires chromedp:\n%s", gomod)
	}
	tools := readFile(t, filepath.Join(dir, "tools_gen.go"))
	for _, want := range []string{
		`Name:        "reboot"`,
		`DestructiveHint: ptr(true)`,
		`ReadOnlyHint: true`,
		"type AddShareInput struct",
		`json:"name"`,
		`json:"verbose,omitempty"`,
		"*bool",
		"*int64",
		"*float64",
		"[]any",
		"map[string]any",
	} {
		if !strings.Contains(tools, want) {
			t.Errorf("tools_gen.go lacks %q", want)
		}
	}
	for _, header := range []string{"Cookie", "Accept-Encoding"} {
		if strings.Contains(tools, `"`+header+`"`) {
			t.Errorf("tools_gen.go replays the %s header", header)
		}
	}
	readme := readFile(t, filepath.Join(dir, "README.md"))
	for _, want := range []string{"NAS_URL", "NAS_USER", "NAS_PASSWORD", "NAS_INSECURE", "NAS_FILES_DIR", "claude mcp add --transport stdio", "go build -o nas-mcp .", "mcpServers"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README.md lacks %q", want)
		}
	}
}

func TestGenerateBrowserModeCompiles(t *testing.T) {
	t.Parallel()
	dir := generateAndBuild(t, browserSpec())
	if _, err := os.Stat(filepath.Join(dir, "browserlogin_gen.go")); err != nil {
		t.Errorf("browser mode did not write browserlogin_gen.go: %v", err)
	}
	gomod := readFile(t, filepath.Join(dir, "go.mod"))
	for _, want := range []string{"github.com/chromedp/chromedp " + ChromedpVersion, "github.com/chromedp/cdproto " + CdprotoVersion} {
		if !strings.Contains(gomod, want) {
			t.Errorf("go.mod lacks %q:\n%s", want, gomod)
		}
	}
	if readme := readFile(t, filepath.Join(dir, "README.md")); !strings.Contains(readme, "Chrome") {
		t.Error("browser-mode README does not mention Chrome")
	}
}

func TestGenerateNoAuthCompiles(t *testing.T) {
	t.Parallel()
	s := httpSpec()
	s.Auth = spec.Auth{Mode: "none"}
	s.Tools = s.Tools[:2]
	generateAndBuild(t, s)
}

func TestGenerateCompilesOddNames(t *testing.T) {
	t.Parallel()
	s := httpSpec()
	tool := func(name string, inputs ...spec.Input) spec.Tool {
		return spec.Tool{
			Name: name, Description: "Odd `name` with \"quotes\" and a \\ backslash.", Enabled: true, Kind: "change",
			Request: spec.Request{Method: "POST", Path: "/api.php", BodyType: "form", Body: map[string]any{"act": name}},
			Inputs:  inputs,
			Source:  spec.Source{Key: "POST /api.php act=" + name},
		}
	}
	s.Tools = []spec.Tool{
		tool("type", spec.Input{Name: "type", Type: "string", In: "body", Field: "type", Required: true, Description: "a=b starts like a WORD= tag"}),
		tool("x_2fa_setup", spec.Input{Name: "disk_id", Type: "integer", In: "body", Field: "disk_id"}, spec.Input{Name: "diskId", Type: "integer", In: "body", Field: "diskId"}),
		tool("list_disks"),
		tool("list_disks_2", spec.Input{Name: "func", Type: "string", In: "query", Field: "func", Description: "Has a `backtick`."}),
		tool("list_disks2"),
		tool("client"),
		tool("string"),
		tool("x_9", spec.Input{Name: "A", Type: "boolean", In: "body", Field: "A"}, spec.Input{Name: "a", Type: "boolean", In: "body", Field: "a"}),
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("test spec is invalid: %v", err)
	}
	dir := generateAndBuild(t, s)
	tools := readFile(t, filepath.Join(dir, "tools_gen.go"))
	for _, want := range []string{"type ToolTypeInput struct", "type X2faSetupInput struct", "type ListDisks2Input struct", "type ToolStringInput struct"} {
		if !strings.Contains(tools, want) {
			t.Errorf("tools_gen.go lacks %q", want)
		}
	}
}

func TestDisabledToolOmitted(t *testing.T) {
	s := httpSpec()
	s.Tools = append(s.Tools, spec.Tool{
		Name: "secret_wipe_everything", Description: "x", Enabled: false, Kind: "destructive",
		Request: spec.Request{Method: "POST", Path: "/api.php", BodyType: "json", Body: map[string]any{"act": "wipe"}},
		Source:  spec.Source{Key: "POST /api.php act=wipe"},
	})
	dir := t.TempDir()
	if _, err := Generate(s, Options{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	if tools := readFile(t, filepath.Join(dir, "tools_gen.go")); strings.Contains(tools, "secret_wipe_everything") || strings.Contains(tools, `"wipe"`) {
		t.Error("disabled tool appears in tools_gen.go")
	}
	if !strings.Contains(readFile(t, filepath.Join(dir, "tools_gen.go")), `"reboot"`) {
		t.Error("enabled tool missing from tools_gen.go")
	}
}

func TestCustomGoPreserved(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.go")
	if err := os.WriteFile(custom, []byte("package main\n\n// mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := Generate(httpSpec(), Options{OutDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, custom); got != "package main\n\n// mine\n" {
		t.Errorf("custom.go changed:\n%s", got)
	}
	for _, f := range files {
		if f == "custom.go" {
			t.Error("Generate reported writing custom.go")
		}
	}

	// A fresh directory gets a custom.go, and regenerating keeps it.
	dir2 := t.TempDir()
	files, err = Generate(httpSpec(), Options{OutDir: dir2})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(files, "custom.go") {
		t.Errorf("files = %v, want custom.go", files)
	}
	c2 := filepath.Join(dir2, "custom.go")
	if !strings.Contains(readFile(t, c2), "func registerCustom(s *mcp.Server, c *Client)") {
		t.Error("custom.go lacks the registerCustom hook")
	}
	if strings.Contains(readFile(t, c2), "DO NOT EDIT") {
		t.Error("custom.go says DO NOT EDIT")
	}
	if err := os.WriteFile(c2, []byte(readFile(t, c2)+"// mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(httpSpec(), Options{OutDir: dir2}); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if !strings.HasSuffix(readFile(t, c2), "// mine\n") {
		t.Error("regenerating overwrote custom.go")
	}
}

func TestGenerateRefusesForeignFiles(t *testing.T) {
	dir := t.TempDir()
	mainGo := filepath.Join(dir, "main.go")
	const mine = "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(mainGo, []byte(mine), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Generate(httpSpec(), Options{OutDir: dir})
	if err == nil || !strings.Contains(err.Error(), "main.go") {
		t.Fatalf("err = %v, want a refusal naming main.go", err)
	}
	if readFile(t, mainGo) != mine {
		t.Error("main.go was overwritten")
	}
}

func TestGenerateRemovesStaleBrowserLogin(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(browserSpec(), Options{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "browserlogin_gen.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(httpSpec(), Options{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "browserlogin_gen.go")); !os.IsNotExist(err) {
		t.Errorf("stale browserlogin_gen.go left behind (err %v)", err)
	}
}

func TestGenerateRejectsInvalidSpecAndTarget(t *testing.T) {
	s := httpSpec()
	s.Tools[0].Name = "Bad Name"
	if _, err := Generate(s, Options{OutDir: t.TempDir()}); err == nil {
		t.Error("invalid spec: no error")
	}
	if _, err := Generate(httpSpec(), Options{Target: "rust", OutDir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "rust") {
		t.Errorf("target rust: err = %v", err)
	}
	if _, err := Generate(httpSpec(), Options{OutDir: t.TempDir(), ModulePath: "bad path"}); err == nil {
		t.Error("module path with a space: no error")
	}
}

func TestGenerateDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	files, err := Generate(httpSpec(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no files")
	}
	gomod := readFile(t, filepath.Join(dir, "nas-mcp", "go.mod"))
	if !strings.Contains(gomod, "module nas-mcp\n") || !strings.Contains(gomod, "go 1.26") {
		t.Errorf("go.mod:\n%s", gomod)
	}
	if !strings.Contains(readFile(t, filepath.Join(dir, "nas-mcp", "main.go")), `"nas-mcp"`) {
		t.Error("main.go lacks the server name")
	}
}

func TestNoSecretsInOutput(t *testing.T) {
	t.Setenv("NAS_URL", "http://10.9.8.7")
	t.Setenv("NAS_USER", "env-user-xyzzy")
	t.Setenv("NAS_PASSWORD", "env-password-plugh")
	s := httpSpec()
	s.Tools[0].Response.Example = map[string]any{"ok": true, "data": map[string]any{"token": "REDACTED", "sid": "REDACTED"}}
	s.Tools[1].Inputs[0].Example = "REDACTED"
	dir := t.TempDir()
	if _, err := Generate(s, Options{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	passwordUses := 0
	for _, e := range entries {
		text := readFile(t, filepath.Join(dir, e.Name()))
		for _, secret := range []string{"10.9.8.7", "env-user-xyzzy", "env-password-plugh", "REDACTED"} {
			if strings.Contains(text, secret) {
				t.Errorf("%s contains %q", e.Name(), secret)
			}
		}
		n := strings.Count(text, "{{password}}")
		if n > 0 && e.Name() != "client_gen.go" {
			t.Errorf("%s contains {{password}}", e.Name())
		}
		passwordUses += n
	}
	if passwordUses != 1 {
		t.Errorf("{{password}} appears %d times, want once (the login template)", passwordUses)
	}
}

func TestGeneratedGofmt(t *testing.T) {
	for name, s := range map[string]*spec.Spec{"http": httpSpec(), "browser": browserSpec()} {
		dir := t.TempDir()
		files, err := Generate(s, Options{OutDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if !strings.HasSuffix(f, ".go") {
				continue
			}
			src := []byte(readFile(t, filepath.Join(dir, f)))
			out, err := format.Source(src)
			if err != nil {
				t.Errorf("%s/%s: %v", name, f, err)
				continue
			}
			if !bytes.Equal(out, src) {
				t.Errorf("%s/%s is not gofmt-clean", name, f)
			}
			if f != "custom.go" && !strings.HasPrefix(string(src), "// Code generated by har2mcp; DO NOT EDIT.") {
				t.Errorf("%s/%s lacks the generated-code header", name, f)
			}
		}
	}
}

func TestGoNames(t *testing.T) {
	cases := map[string]string{
		"list_disks":  "ListDisks",
		"x_2fa_setup": "X2faSetup",
		"type":        "ToolType",
		"string":      "ToolString",
		"a":           "A",
	}
	for in, want := range cases {
		if got := toolGoName(in); got != want {
			t.Errorf("toolGoName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := camel("API_key"); got != "APIKey" {
		t.Errorf("camel(API_key) = %q", got)
	}
}

func TestGoLiteral(t *testing.T) {
	got, err := goLiteral(map[string]any{
		"s": "a\"b", "n": 3, "f": 1.5, "big": int64(5000000000), "huge": "x", "b": true, "nil": nil,
		"list": []string{"x", "y"}, "m": map[string]any{"k": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	src := "package p\n\nvar v = " + got + "\n\nfunc num(s string) any { return s }\n"
	if _, err := format.Source([]byte(src)); err != nil {
		t.Fatalf("literal does not parse: %v\n%s", err, got)
	}
	for _, want := range []string{`"s": "a\"b"`, `"n": 3`, `"f": 1.5`, `"big": int64(5000000000)`, `"b": true`, `"nil": nil`, `[]any{"x", "y"}`, `map[string]any{"k": 1}`} {
		if !strings.Contains(got, want) {
			t.Errorf("literal lacks %q:\n%s", want, got)
		}
	}
	got, err = goLiteral(map[string]any{"huge": 123456789012345678901234567890.0, "int": uint64(18446744073709551615)})
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`"int": num\("18446744073709551615"\)`).MatchString(got) {
		t.Errorf("uint64 max literal = %s", got)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
