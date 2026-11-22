package spec

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// sampleSpec has one tool of each kind, an upload, a download and a
// path-parameter tool. Its Generated hashes match its fields.
func sampleSpec() *Spec {
	s := &Spec{
		Har2mcp: FormatVersion,
		Service: Service{Name: "nas", BaseURL: "http://192.168.1.10:8181", Hosts: []string{"192.168.1.10:8181"}},
		Auth: Auth{
			Mode: "http",
			Login: &Login{
				PageURL: "http://192.168.1.10:8181/",
				Request: Request{
					Method:   "POST",
					Path:     "/api/login",
					BodyType: "json",
					Body:     map[string]any{"username": "{{username}}", "password": "{{password}}"},
				},
				Form: &LoginForm{Username: "#username", Password: "#password", Submit: "#login"},
			},
			Session: Session{
				Cookies: []string{"NASSESSID"},
				Tokens: []TokenFlow{{
					Name: "csrf",
					From: TokenRef{ResponseJSON: "data.token"},
					To:   TokenRef{Header: "X-Csrf-Token"},
				}, {
					Name:   "bearer",
					From:   TokenRef{ResponseJSON: "data.token"},
					To:     TokenRef{Header: "Authorization"},
					Prefix: "Bearer ",
				}},
			},
			ReloginOn:           []int{401, 403},
			ReloginBodyContains: "not logged in",
		},
		Tools: []Tool{
			{
				Name:        "list_disks",
				Description: "List disks. Calls POST /api.php (act=getdisklist).",
				Enabled:     true,
				Kind:        "read",
				Request: Request{
					Method:        "POST",
					Path:          "/api.php",
					BodyType:      "json",
					Body:          map[string]any{"act": "getdisklist"},
					Discriminator: "act",
				},
				Inputs: []Input{},
				Response: Response{
					ContentType: "application/json",
					Schema: map[string]any{
						"type": "object",
						"properties": map[string]any{
							"ok":   map[string]any{"type": "boolean"},
							"data": map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
						},
					},
					Example: map[string]any{"ok": true, "data": []any{map[string]any{"id": "sda", "size_gb": 4000}}},
				},
				Source: Source{Key: "POST /api.php act=getdisklist", Steps: []string{"list disks"}, Samples: 2, Trigger: "Disks"},
			},
			{
				Name:        "add_share",
				Description: "Add share.",
				Enabled:     true,
				Kind:        "change",
				Request: Request{
					Method: "POST", Path: "/api.php", BodyType: "json",
					Body: map[string]any{"act": "addshare", "lang": "en"}, Discriminator: "act",
				},
				Inputs: []Input{{Name: "name", Type: "string", Description: "Share name", Required: true, In: "body", Field: "name", Example: "media"}},
				Source: Source{Key: "POST /api.php act=addshare", Steps: []string{"add share"}, Samples: 1},
				Review: true, ReviewNotes: []string{"body.lang has one sample"},
			},
			{
				Name:        "reboot",
				Description: "Reboot.",
				Enabled:     false,
				Kind:        "destructive",
				Request:     Request{Method: "POST", Path: "/api.php", BodyType: "json", Body: map[string]any{"act": "reboot"}, Discriminator: "act"},
				Source:      Source{Key: "POST /api.php act=reboot", Steps: []string{"reboot"}, Samples: 1},
			},
			{
				Name:    "upload_file",
				Enabled: true,
				Kind:    "change",
				Request: Request{Method: "POST", Path: "/api/upload", BodyType: "multipart"},
				File:    &FileOp{Direction: "upload", Part: "file", Chunked: &Chunking{OffsetField: "offset", TotalField: "total", ChunkSize: 1048576}},
				Inputs: []Input{
					{Name: "local_path", Type: "string", Required: true, In: "file", Field: "file"},
					{Name: "path", Type: "string", Required: true, In: "body", Field: "path", Example: "/public"},
				},
				Source: Source{Key: "POST /api/upload", Samples: 1},
			},
			{
				Name:    "download_file",
				Enabled: true,
				Kind:    "read",
				Request: Request{Method: "GET", Path: "/api/download"},
				File:    &FileOp{Direction: "download"},
				Inputs: []Input{
					{Name: "path", Type: "string", Required: true, In: "query", Field: "path"},
					{Name: "local_path", Type: "string", Required: true, In: "file"},
				},
				Response: Response{ContentType: "application/octet-stream"},
				Source:   Source{Key: "GET /api/download", Samples: 1},
			},
			{
				Name:    "get_disk",
				Enabled: true,
				Kind:    "read",
				Request: Request{Method: "GET", Path: "/api/v1/disks/{id}", Query: map[string]any{"verbose": 1}, Headers: map[string]string{"Accept": "application/json"}},
				Inputs:  []Input{{Name: "id", Type: "integer", Required: true, In: "path", Field: "id", Example: 0}},
				Source:  Source{Key: "GET /api/v1/disks/{id}", Samples: 2},
			},
		},
	}
	stampGenerated(s)
	return s
}

// stampGenerated fills Generated the way analyze does.
func stampGenerated(s *Spec) {
	for i := range s.Tools {
		t := &s.Tools[i]
		t.Generated = map[string]string{
			"name":        FieldHash(t.Name),
			"description": FieldHash(t.Description),
			"enabled":     FieldHash(t.Enabled),
			"kind":        FieldHash(t.Kind),
			"inputs":      FieldHash(t.Inputs),
		}
	}
	s.AuthGenerated = FieldHash(s.Auth)
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nas.spec.yaml")
	in := sampleSpec()
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Har2mcp != FormatVersion || !reflect.DeepEqual(out.Service, in.Service) {
		t.Fatalf("header = %d %+v", out.Har2mcp, out.Service)
	}
	if !reflect.DeepEqual(out.Auth, in.Auth) {
		t.Errorf("auth changed:\n got %#v\nwant %#v", out.Auth, in.Auth)
	}
	if len(out.Tools) != len(in.Tools) {
		t.Fatalf("tools = %d", len(out.Tools))
	}
	kinds := map[string]bool{}
	for i := range in.Tools {
		a, b := in.Tools[i], out.Tools[i]
		kinds[b.Kind] = true
		if a.Name != b.Name || a.Description != b.Description || a.Enabled != b.Enabled || a.Kind != b.Kind {
			t.Errorf("tool %d text fields changed: %+v", i, b)
		}
		if !reflect.DeepEqual(a.File, b.File) || !reflect.DeepEqual(a.Source, b.Source) || !reflect.DeepEqual(a.Generated, b.Generated) {
			t.Errorf("tool %s file/source/generated changed:\n got %+v %+v %+v", a.Name, b.File, b.Source, b.Generated)
		}
		if a.Review != b.Review || !reflect.DeepEqual(a.ReviewNotes, b.ReviewNotes) {
			t.Errorf("tool %s review changed", a.Name)
		}
		if b.Request.Method != a.Request.Method || b.Request.Path != a.Request.Path || b.Request.Discriminator != a.Request.Discriminator {
			t.Errorf("tool %s request changed: %+v", a.Name, b.Request)
		}
	}
	for _, k := range []string{"read", "change", "destructive"} {
		if !kinds[k] {
			t.Errorf("no %s tool after round trip", k)
		}
	}
	up := out.Tools[3]
	if up.File == nil || up.File.Direction != "upload" || up.File.Part != "file" || up.File.Chunked.ChunkSize != 1048576 {
		t.Errorf("upload FileOp = %+v", up.File)
	}
	if up.Inputs[0].In != "file" || up.Inputs[1].Example != "/public" {
		t.Errorf("upload inputs = %+v", up.Inputs)
	}
	if got := out.Tools[0].Request.Body["act"]; got != "getdisklist" {
		t.Errorf("fixed body = %v", out.Tools[0].Request.Body)
	}
	if out.Tools[2].Enabled {
		t.Error("enabled: false was lost")
	}
	if err := out.Validate(); err != nil {
		t.Errorf("round-tripped spec is invalid: %v", err)
	}
}

// Hand-edit detection compares FieldHash of loaded fields with hashes taken
// at analysis time, so a save and load must not change any hash.
func TestFieldHashStableAcrossSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nas.spec.yaml")
	in := sampleSpec()
	in.Tools[2].Inputs = nil // nil and empty inputs must hash alike
	in.Auth.Session.Cookies = []string{}
	in.Tools[5].Inputs[0].Example = false // a zero example must survive omitempty
	stampGenerated(in)
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := FieldHash(out.Auth); got != out.AuthGenerated {
		t.Errorf("auth hash changed after load: %s != %s", got, out.AuthGenerated)
	}
	for _, tool := range out.Tools {
		for field, v := range map[string]any{
			"name": tool.Name, "description": tool.Description, "enabled": tool.Enabled,
			"kind": tool.Kind, "inputs": tool.Inputs,
		} {
			if got := FieldHash(v); got != tool.Generated[field] {
				t.Errorf("%s.%s hash changed after load: %s != %s", tool.Name, field, got, tool.Generated[field])
			}
		}
	}
}

func TestFieldHash(t *testing.T) {
	h := FieldHash("list_disks")
	if len(h) != 8 || strings.Trim(h, "0123456789abcdef") != "" {
		t.Fatalf("FieldHash = %q, want 8 hex chars", h)
	}
	// sha256(`"list_disks"`)[:8]
	if h != FieldHash("list_disks") || h == FieldHash("get_disks") {
		t.Fatal("FieldHash is not a stable function of its input")
	}
	if FieldHash([]Input(nil)) != FieldHash([]Input{}) {
		t.Error("nil and empty slices hash differently")
	}
	if FieldHash(true) == FieldHash(false) {
		t.Error("true and false hash alike")
	}
}

func TestSaveMode0644AndStable(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.yaml"), filepath.Join(dir, "b.yaml")
	if err := Save(a, sampleSpec()); err != nil {
		t.Fatal(err)
	}
	if err := Save(b, sampleSpec()); err != nil {
		t.Fatal(err)
	}
	ba, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	if string(ba) != string(bb) {
		t.Fatal("two saves of the same spec differ")
	}
	text := string(ba)
	for _, want := range []string{"har2mcp: 1\n", "service:\n  name: nas\n", "  mode: http\n", "relogin_on:", "response_json: data.token", "auth_generated:", "body_type: json", "discriminator: act", "enabled: false"} {
		if !strings.Contains(text, want) {
			t.Errorf("saved spec lacks %q", want)
		}
	}
	if strings.Index(text, "service:") > strings.Index(text, "tools:") {
		t.Error("keys are not in declaration order")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(a)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
		}
	}
}

func TestLoadRejects(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"typo.yaml":    "har2mcp: 1\nservice:\n  name: nas\nauth:\n  mode: none\ntools:\n  - name: a\n    kind: read\n    enable: true\n    request: {method: GET, path: /a}\n",
		"noformat.yml": "service:\n  name: nas\nauth:\n  mode: none\n",
		"future.yaml":  "har2mcp: 99\nservice:\n  name: nas\nauth:\n  mode: none\n",
		"invalid.yaml": "har2mcp: 1\nservice:\n  name: Bad Name\nauth:\n  mode: none\n",
		"har.json":     `{"log":{"version":"1.2","entries":[]}}`,
		"empty.yaml":   "",
	}
	for name, body := range cases {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("Load(%s) succeeded, want error", name)
		} else if !strings.Contains(err.Error(), name) {
			t.Errorf("Load(%s) error does not name the file: %v", name, err)
		}
	}
}

func TestValidate(t *testing.T) {
	if err := sampleSpec().Validate(); err != nil {
		t.Fatalf("sample spec invalid: %v", err)
	}
	none := &Spec{Har2mcp: 1, Service: Service{Name: "plug"}, Auth: Auth{Mode: "none"},
		Tools: []Tool{{Name: "status", Kind: "read", Enabled: true, Request: Request{Method: "GET", Path: "/status"}}}}
	if err := none.Validate(); err != nil {
		t.Fatalf("minimal no-auth spec invalid: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(s *Spec)
		want   string // substring of the error
	}{
		{"bad service name", func(s *Spec) { s.Service.Name = "My NAS" }, "service.name"},
		{"service name too long", func(s *Spec) { s.Service.Name = strings.Repeat("a", 33) }, "service.name"},
		{"bad tool name", func(s *Spec) { s.Tools[0].Name = "List-Disks" }, "List-Disks"},
		{"tool name too long", func(s *Spec) { s.Tools[0].Name = strings.Repeat("a", 65) }, "name"},
		{"duplicate tool name", func(s *Spec) { s.Tools[1].Name = "list_disks" }, "duplicate"},
		{"bad kind", func(s *Spec) { s.Tools[0].Kind = "write" }, "kind"},
		{"bad mode", func(s *Spec) { s.Auth.Mode = "oauth" }, "auth.mode"},
		{"empty mode", func(s *Spec) { s.Auth.Mode = "" }, "auth.mode"},
		{"bad input in", func(s *Spec) { s.Tools[1].Inputs[0].In = "header" }, "in"},
		{"bad input type", func(s *Spec) { s.Tools[1].Inputs[0].Type = "text" }, "type"},
		{"bad input name", func(s *Spec) { s.Tools[1].Inputs[0].Name = "share name" }, "share name"},
		{"duplicate input name", func(s *Spec) { s.Tools[3].Inputs[1].Name = "local_path" }, "duplicate"},
		{"browser without form", func(s *Spec) { s.Auth.Mode = "browser"; s.Auth.Login.Form = nil }, "form"},
		{"browser form without selectors", func(s *Spec) { s.Auth.Mode = "browser"; s.Auth.Login.Form.Password = "" }, "form"},
		{"http without login", func(s *Spec) { s.Auth.Login = nil }, "auth.login"},
		{"browser without login", func(s *Spec) { s.Auth.Mode = "browser"; s.Auth.Login = nil }, "auth.login"},
		{"http login without path", func(s *Spec) { s.Auth.Login.Request.Path = "" }, "auth.login.request"},
		{"placeholder without input", func(s *Spec) { s.Tools[5].Inputs = nil }, "{id}"},
		{"placeholder input in query", func(s *Spec) { s.Tools[5].Inputs[0].In = "query" }, "{id}"},
		{"path input without placeholder", func(s *Spec) { s.Tools[5].Request.Path = "/api/v1/disks" }, "placeholder"},
		{"token ref with no field", func(s *Spec) { s.Auth.Session.Tokens[0].From = TokenRef{} }, "exactly one"},
		{"token ref with two fields", func(s *Spec) { s.Auth.Session.Tokens[0].To.Cookie = "csrftoken" }, "exactly one"},
		{"token prefix with a newline", func(s *Spec) { s.Auth.Session.Tokens[1].Prefix = "Bearer\n" }, "prefix"},
		{"bad relogin status", func(s *Spec) { s.Auth.ReloginOn = []int{4010} }, "relogin_on"},
		{"bad method", func(s *Spec) { s.Tools[0].Request.Method = "" }, "method"},
		{"relative path", func(s *Spec) { s.Tools[0].Request.Path = "api.php" }, "path"},
		{"bad body type", func(s *Spec) { s.Tools[0].Request.BodyType = "xml" }, "body_type"},
		{"bad file direction", func(s *Spec) { s.Tools[3].File.Direction = "sideways" }, "direction"},
		{"upload without part", func(s *Spec) { s.Tools[3].File.Part = "" }, "part"},
		{"file tool without file input", func(s *Spec) { s.Tools[4].Inputs = s.Tools[4].Inputs[:1] }, "file"},
		{"file input on plain tool", func(s *Spec) { s.Tools[1].Inputs[0].In = "file" }, "file"},
		{"chunking without size", func(s *Spec) { s.Tools[3].File.Chunked.ChunkSize = 0 }, "chunk"},
		{"bad format version", func(s *Spec) { s.Har2mcp = 2 }, "har2mcp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := sampleSpec()
			c.mutate(s)
			err := s.Validate()
			if err == nil {
				t.Fatal("Validate accepted an invalid spec")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestEnvPrefix(t *testing.T) {
	s := &Spec{Service: Service{Name: "my_nas2"}}
	if got := s.EnvPrefix(); got != "MY_NAS2" {
		t.Fatalf("EnvPrefix = %q", got)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"List Disks", 64, "list_disks"},
		{"🔥 Reboot!!", 64, "reboot"},
		{"", 64, "unnamed"},
		{"!!!", 64, "unnamed"},
		{"2fa setup", 64, "x_2fa_setup"},
		{"Ünïcode Shares", 64, "unicode_shares"},
		{"Straße öffnen", 64, "strasse_offnen"},
		{"getDiskList", 64, "get_disk_list"},
		{"XMLHttpRequest", 64, "xml_http_request"},
		{"getsysinfo", 64, "getsysinfo"},
		{"/api/v1/disks", 64, "api_v1_disks"},
		{"  already_snake__case  ", 64, "already_snake_case"},
		{"type", 64, "type"},
		{"aaaa bbbb cccc", 10, "aaaa_bbbb"},
		{"2fa setup", 4, "x_2f"},
		{"日本語", 64, "unnamed"},
		{strings.Repeat("word ", 30), 64, ""}, // checked by the length rule below
	}
	for _, c := range cases {
		got := SanitizeName(c.in, c.max)
		if c.want != "" && got != c.want {
			t.Errorf("SanitizeName(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
		if len(got) > c.max {
			t.Errorf("SanitizeName(%q, %d) = %q is longer than %d", c.in, c.max, got, c.max)
		}
		if !toolNameRE.MatchString(got) || strings.HasSuffix(got, "_") || strings.Contains(got, "__") {
			t.Errorf("SanitizeName(%q, %d) = %q is not clean snake_case", c.in, c.max, got)
		}
	}
	if got := SanitizeName("List Disks", 0); got != "list_disks" {
		t.Errorf("maxLen 0 should mean the 64-character default, got %q", got)
	}
}

func TestUniqueName(t *testing.T) {
	taken := map[string]bool{}
	a := UniqueName("list_disks", taken)
	b := UniqueName("list_disks", taken)
	c := UniqueName("list_disks", taken)
	if a != "list_disks" || b != "list_disks_2" || c != "list_disks_3" {
		t.Fatalf("got %q %q %q", a, b, c)
	}
	if !taken["list_disks_2"] {
		t.Fatal("UniqueName did not record the name it returned")
	}
	long := strings.Repeat("a", 64)
	taken[long] = true
	if got := UniqueName(long, taken); len(got) > 64 || got != strings.Repeat("a", 62)+"_2" {
		t.Fatalf("UniqueName of a 64-character name = %q", got)
	}
	if got := UniqueName("free", nil); got != "free" {
		t.Fatalf("nil map: %q", got)
	}
}

func TestGoKeywords(t *testing.T) {
	for _, w := range []string{"type", "func", "range", "string", "error", "nil", "true", "len", "any", "iota"} {
		if !GoKeywords[w] {
			t.Errorf("GoKeywords lacks %q", w)
		}
	}
	if GoKeywords["list_disks"] {
		t.Error("list_disks is not a keyword")
	}
}
