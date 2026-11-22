package analyze

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

func mustAnalyze(t *testing.T, opts Options, hars ...*har.HAR) *spec.Spec {
	t.Helper()
	s, err := Analyze(hars, opts)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("Analyze produced an invalid spec: %v", err)
	}
	return s
}

func toolByName(t *testing.T, s *spec.Spec, name string) *spec.Tool {
	t.Helper()
	for i := range s.Tools {
		if s.Tools[i].Name == name {
			return &s.Tools[i]
		}
	}
	t.Fatalf("no tool %q; tools: %v", name, toolNames(s))
	return nil
}

func toolByKey(t *testing.T, s *spec.Spec, key string) *spec.Tool {
	t.Helper()
	for i := range s.Tools {
		if s.Tools[i].Source.Key == key {
			return &s.Tools[i]
		}
	}
	var keys []string
	for _, tl := range s.Tools {
		keys = append(keys, tl.Source.Key)
	}
	t.Fatalf("no tool with key %q; keys: %q", key, keys)
	return nil
}

func toolNames(s *spec.Spec) []string {
	var out []string
	for _, t := range s.Tools {
		out = append(out, t.Name)
	}
	return out
}

func inputByName(t *testing.T, tl *spec.Tool, name string) spec.Input {
	t.Helper()
	for _, in := range tl.Inputs {
		if in.Name == name {
			return in
		}
	}
	t.Fatalf("tool %s has no input %q; inputs: %+v", tl.Name, name, tl.Inputs)
	return spec.Input{}
}

func specYAML(t *testing.T, s *spec.Spec) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.spec.yaml")
	if err := spec.Save(p, s); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestFilterDropsStaticAndForeign(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.static()
	b.add(req{method: "POST", url: "https://www.google-analytics.com/g/collect?v=2&tid=G-123", reqMime: "text/plain", reqBody: "x",
		respMime: "application/json", respBody: `{"ok":true}`, resourceType: "fetch"})
	b.add(req{method: "GET", url: "/static/font.woff2", respMime: "font/woff2", respBody: "wOF2"})
	b.add(req{method: "GET", url: "/favicon.ico", respMime: "image/x-icon", respBody: "ico"})
	b.add(req{method: "OPTIONS", url: "/api.php", status: 204})
	b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks)
	s := mustAnalyze(t, Options{}, b.build())

	if len(s.Tools) != 1 {
		t.Fatalf("want only the /api.php tool, got %d: %v", len(s.Tools), toolNames(s))
	}
	if got := s.Tools[0].Request.Path; got != "/api.php" {
		t.Fatalf("path = %q", got)
	}
	if !reflect.DeepEqual(s.Service.Hosts, []string{"192.168.1.50"}) {
		t.Fatalf("hosts = %q", s.Service.Hosts)
	}
	if s.Service.BaseURL != fxBase {
		t.Fatalf("base url = %q", s.Service.BaseURL)
	}
	if s.Auth.Mode != "none" {
		t.Fatalf("auth mode = %q, want none (no login recorded)", s.Auth.Mode)
	}
}

func TestRPCSplitByAct(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("login").login(fxUser, fxPassword).endStep()
	b.api("getdisklist", nil, fxDisks)
	b.api("getsysinfo", nil, fxSysinfo)
	b.api("getdisklist", nil, fxDisks)
	b.api("getsharelist", nil, map[string]any{"ok": true, "data": []any{"public"}})
	b.api("reboot", nil, fxOK)
	s := mustAnalyze(t, Options{}, b.build())

	if len(s.Tools) != 4 {
		t.Fatalf("want 4 tools, got %v", toolNames(s))
	}
	for _, act := range []string{"getdisklist", "getsysinfo", "getsharelist", "reboot"} {
		tl := toolByKey(t, s, "POST /api.php act="+act)
		if tl.Request.Discriminator != "act" {
			t.Errorf("%s: discriminator = %q", act, tl.Request.Discriminator)
		}
		if tl.Request.Body["act"] != act {
			t.Errorf("%s: body act = %v", act, tl.Request.Body["act"])
		}
		if tl.Request.BodyType != "json" || tl.Request.Method != "POST" || tl.Request.Path != "/api.php" {
			t.Errorf("%s: request = %+v", act, tl.Request)
		}
		for _, in := range tl.Inputs {
			if in.Field == "act" {
				t.Errorf("%s: act must be fixed, not an input", act)
			}
		}
	}
	if got := toolByKey(t, s, "POST /api.php act=getdisklist").Source.Samples; got != 2 {
		t.Errorf("getdisklist samples = %d, want 2", got)
	}
}

func TestRESTPathParams(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("disk details").click("Disk 1").get("/api/v1/disks/1", map[string]any{"id": 1, "model": "WD Red"})
	b.click("Disk 2").get("/api/v1/disks/2", map[string]any{"id": 2, "model": "WD Red"}).endStep()
	b.step("list disks").click("Disks").get("/api/v1/disks", []any{1, 2}).endStep()
	b.step("list shares").click("Shares").get("/api/v1/shares", []any{"public"}).endStep()
	s := mustAnalyze(t, Options{}, b.build())

	tl := toolByKey(t, s, "GET /api/v1/disks/{id}")
	if tl.Request.Path != "/api/v1/disks/{id}" || tl.Source.Samples != 2 {
		t.Fatalf("tool = %+v", tl)
	}
	in := inputByName(t, tl, "id")
	if in.In != "path" || in.Type != "integer" || !in.Required {
		t.Fatalf("id input = %+v", in)
	}
	// Sibling collections are not merged into a placeholder.
	toolByKey(t, s, "GET /api/v1/disks")
	toolByKey(t, s, "GET /api/v1/shares")
}

func TestRESTPathParamFromResponseValues(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("list disks").click("Disks").get("/api/v1/disks", []any{"sda", "sdb"}).endStep()
	b.step("smart").click("sda").get("/api/v1/disks/sda/smart", map[string]any{"ok": true})
	b.click("sdb").get("/api/v1/disks/sdb/smart", map[string]any{"ok": true}).endStep()
	s := mustAnalyze(t, Options{}, b.build())
	tl := toolByKey(t, s, "GET /api/v1/disks/{id}/smart")
	if in := inputByName(t, tl, "id"); in.Type != "string" || in.In != "path" {
		t.Fatalf("id input = %+v", in)
	}
}

func TestParamsVaryingAndTyped(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("login").login(fxUser, fxPassword).endStep()
	b.step("add share", typed("Share name", "share-name", "#share-name", "text", "media")).
		click("Add share").api("addshare", map[string]any{"name": "media", "lang": "en"}, fxOK).endStep()
	b.step("add share", typed("Share name", "share-name", "#share-name", "text", "photos")).
		click("Add share").api("addshare", map[string]any{"name": "photos", "lang": "en"}, fxOK).endStep()
	s := mustAnalyze(t, Options{}, b.build())

	tl := toolByName(t, s, "add_share")
	in := inputByName(t, tl, "name")
	if !in.Required || in.In != "body" || in.Field != "name" || in.Type != "string" {
		t.Fatalf("name input = %+v", in)
	}
	if in.Description != "Share name" {
		t.Errorf("name description = %q, want the typed field's label", in.Description)
	}
	if tl.Request.Body["lang"] != "en" {
		t.Fatalf("lang should stay fixed: body = %v", tl.Request.Body)
	}
	for _, in := range tl.Inputs {
		if in.Field == "lang" {
			t.Fatalf("lang must not be an input")
		}
	}
	if tl.Review {
		t.Fatalf("unexpected review: %q", tl.ReviewNotes)
	}

	t.Run("single sample typed", func(t *testing.T) {
		s := mustAnalyze(t, Options{}, fakenasRecording().build())
		for _, name := range []string{"add_share", "delete_share"} {
			tl := toolByName(t, s, name)
			if in := inputByName(t, tl, "name"); !in.Required || in.In != "body" || in.Field != "name" {
				t.Errorf("%s: name input = %+v", name, in)
			}
			if tl.Review {
				t.Errorf("%s: unexpected review %q", name, tl.ReviewNotes)
			}
		}
	})
}

func TestSingleSampleFlagsReview(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("login").login(fxUser, fxPassword).endStep()
	b.step("set fan").click("Fan").api("setfan", map[string]any{"speed": "high"}, fxOK).endStep()
	s := mustAnalyze(t, Options{}, b.build())

	tl := toolByName(t, s, "set_fan")
	if !tl.Review {
		t.Fatalf("want review on a single-sample tool with an untraceable value")
	}
	if !strings.Contains(strings.Join(tl.ReviewNotes, "\n"), `"speed"`) {
		t.Fatalf("review notes should name the field: %q", tl.ReviewNotes)
	}
	if tl.Request.Body["speed"] != "high" {
		t.Fatalf("speed should stay fixed: %v", tl.Request.Body)
	}
}

func TestAuthHTTPMode(t *testing.T) {
	s := mustAnalyze(t, Options{}, fakenasRecording().build())
	a := s.Auth
	if a.Mode != "http" {
		t.Fatalf("mode = %q", a.Mode)
	}
	if a.Login == nil {
		t.Fatal("no login")
	}
	r := a.Login.Request
	if r.Method != "POST" || r.Path != "/api/login" || r.BodyType != "json" {
		t.Fatalf("login request = %+v", r)
	}
	if r.Body["password"] != "{{password}}" || r.Body["username"] != "{{username}}" {
		t.Fatalf("login body = %v", r.Body)
	}
	if !reflect.DeepEqual(a.Session.Cookies, []string{"NASSESSID"}) {
		t.Fatalf("cookies = %q", a.Session.Cookies)
	}
	if len(a.Session.Tokens) != 1 {
		t.Fatalf("tokens = %+v", a.Session.Tokens)
	}
	tf := a.Session.Tokens[0]
	if tf.From != (spec.TokenRef{ResponseJSON: "data.token"}) || tf.To != (spec.TokenRef{Header: "X-Csrf-Token"}) {
		t.Fatalf("token flow = %+v", tf)
	}
	if !reflect.DeepEqual(a.ReloginOn, []int{401, 403}) {
		t.Fatalf("relogin_on = %v", a.ReloginOn)
	}
	if a.ReloginBodyContains != "not logged in" {
		t.Fatalf("relogin_body_contains = %q", a.ReloginBodyContains)
	}
	if a.Review {
		t.Fatalf("unexpected auth review: %q", a.ReviewNotes)
	}
	if a.Login.Form == nil || a.Login.Form.Password != "#password" {
		t.Fatalf("form = %+v", a.Login.Form)
	}
	for _, tl := range s.Tools {
		if tl.Request.Path == "/api/login" {
			t.Errorf("the login request must not be a tool: %s", tl.Name)
		}
		for k := range tl.Request.Headers {
			if strings.EqualFold(k, "X-Csrf-Token") || strings.EqualFold(k, "Cookie") {
				t.Errorf("%s: header %s must be handled by the server, not fixed", tl.Name, k)
			}
		}
		for _, in := range tl.Inputs {
			if strings.EqualFold(in.Name, "X-Csrf-Token") || strings.EqualFold(in.Field, "X-Csrf-Token") || strings.Contains(strings.ToLower(in.Name), "csrf") {
				t.Errorf("%s: CSRF token exposed as input %q", tl.Name, in.Name)
			}
		}
	}
}

func TestAuthBrowserMode(t *testing.T) {
	s := mustAnalyze(t, Options{}, fakenasScrambledRecording().build())
	a := s.Auth
	if a.Mode != "browser" {
		t.Fatalf("mode = %q", a.Mode)
	}
	if a.Login == nil || a.Login.Form == nil {
		t.Fatalf("login = %+v", a.Login)
	}
	if *a.Login.Form != (spec.LoginForm{Username: "#username", Password: "#password", Submit: "#login"}) {
		t.Fatalf("form = %+v", *a.Login.Form)
	}
	if a.Login.PageURL == "" {
		t.Fatal("page_url not set")
	}
	if a.Login.Request.Path != "/api/login" {
		t.Fatalf("login request = %+v", a.Login.Request)
	}
	if !reflect.DeepEqual(a.Session.Cookies, []string{"NASSESSID"}) {
		t.Fatalf("cookies = %q", a.Session.Cookies)
	}
	y := specYAML(t, s)
	for _, secret := range []string{fxPassword, scramble(fxPassword, fxNonce), fxSession, fxCSRF} {
		if strings.Contains(y, secret) {
			t.Errorf("spec contains secret %q", secret)
		}
	}
	toolByName(t, s, "list_disks")
}

func TestAnalyzeDevToolsSanitizedHAR(t *testing.T) {
	b := newDevToolsHAR(fxBase)
	b.static()
	b.login(fxUser, fxPassword) // a plain HAR has no steps and no login capture
	b.api("getdisklist", nil, fxDisks)
	b.api("getsysinfo", nil, fxSysinfo)
	b.api("getdisklist", nil, fxDisks)
	h := b.build()
	for _, e := range h.Log.Entries {
		if e.Request.Header("Cookie") != "" || e.Response.Header("Set-Cookie") != "" {
			t.Fatal("fixture is not sanitized")
		}
	}
	s := mustAnalyze(t, Options{}, h)

	if !s.Auth.Review || len(s.Auth.ReviewNotes) == 0 {
		t.Fatalf("a plain HAR's auth must be flagged for review: %+v", s.Auth)
	}
	toolByName(t, s, "getdisklist")
	toolByName(t, s, "getsysinfo")
	if s.Auth.Mode != "http" || s.Auth.Login == nil || s.Auth.Login.Request.Body["password"] != "{{password}}" {
		t.Fatalf("auth = %+v", s.Auth)
	}
	if strings.Contains(specYAML(t, s), fxPassword) {
		t.Fatal("spec contains the password")
	}
	if len(s.Auth.Session.Tokens) != 1 || s.Auth.Session.Tokens[0].From.ResponseJSON != "data.token" {
		t.Fatalf("tokens = %+v (should be found in the base64 login response)", s.Auth.Session.Tokens)
	}
}

func TestAnalyzeDevToolsNoLogin(t *testing.T) {
	b := newDevToolsHAR(fxBase)
	b.api("getdisklist", nil, fxDisks)
	s := mustAnalyze(t, Options{}, b.build())
	if s.Auth.Mode != "none" || !s.Auth.Review {
		t.Fatalf("auth = %+v", s.Auth)
	}
}

func TestClassify(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("login").login(fxUser, fxPassword).endStep()
	b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks).endStep()
	b.step("add share").click("Add").api("addshare", map[string]any{"name": "media"}, fxOK).endStep()
	b.step("remove share").click("Delete").api("delshare", map[string]any{"name": "media"}, fxOK).endStep()
	b.step("restart nas").click("Restart").api("reboot", nil, fxOK).endStep()
	b.step("wipe disk").click("Go").api("zerofill", map[string]any{"disk": "sdb"}, fxOK).endStep()
	b.step("rename").click("Go").add(req{method: "DELETE", url: "/api/v1/shares/7", respMime: "application/json", respBody: "{}"}).endStep()
	b.step("refresh").click("Go").add(req{method: "GET", url: "/api/v1/status", respMime: "application/json", respBody: "{}"}).endStep()
	s := mustAnalyze(t, Options{}, b.build())

	for key, want := range map[string]string{
		"POST /api.php act=getdisklist": "read",
		"POST /api.php act=addshare":    "change",
		"POST /api.php act=delshare":    "destructive",
		"POST /api.php act=reboot":      "destructive",
		"POST /api.php act=zerofill":    "destructive", // from the step label "wipe disk"
		"DELETE /api/v1/shares/{id}":    "destructive",
		"GET /api/v1/status":            "read",
	} {
		if got := toolByKey(t, s, key).Kind; got != want {
			t.Errorf("%s: kind = %s, want %s", key, got, want)
		}
	}
}

func TestFilesUploadDownload(t *testing.T) {
	s := mustAnalyze(t, Options{}, fakenasRecording().build())

	up := toolByName(t, s, "upload_file")
	if up.File == nil || up.File.Direction != "upload" || up.File.Part != "file" {
		t.Fatalf("upload file op = %+v", up.File)
	}
	if up.Request.BodyType != "multipart" || up.Kind != "change" {
		t.Fatalf("upload request = %+v kind %s", up.Request, up.Kind)
	}
	if len(up.Inputs) != 2 {
		t.Fatalf("upload inputs = %+v", up.Inputs)
	}
	if lp := up.Inputs[0]; lp.Name != "local_path" || lp.In != "file" || !lp.Required || lp.Type != "string" {
		t.Fatalf("upload local_path = %+v", lp)
	}
	if p := up.Inputs[1]; p.Name != "path" || p.In != "body" || p.Field != "path" || !p.Required {
		t.Fatalf("upload path = %+v", p)
	}

	down := toolByName(t, s, "download_file")
	if down.File == nil || down.File.Direction != "download" {
		t.Fatalf("download file op = %+v", down.File)
	}
	if down.Kind != "read" || down.Request.Method != "GET" || down.Request.Path != "/api/download" {
		t.Fatalf("download = %+v kind %s", down.Request, down.Kind)
	}
	if len(down.Inputs) != 2 {
		t.Fatalf("download inputs = %+v", down.Inputs)
	}
	if p := down.Inputs[0]; p.Name != "path" || p.In != "query" || p.Field != "path" || !p.Required {
		t.Fatalf("download path = %+v", p)
	}
	if lp := down.Inputs[1]; lp.Name != "local_path" || lp.In != "file" || !lp.Required {
		t.Fatalf("download local_path = %+v", lp)
	}
	if down.Response.ContentType != "application/octet-stream" || down.Response.Example != nil || down.Response.Schema != nil {
		t.Fatalf("download response = %+v", down.Response)
	}
}

// chunkedUpload posts one chunk of a resumable upload.
func (b *harBuilder) chunk(fields map[string]string, fileName, content string) *harBuilder {
	var params []har.Param
	var keys []string
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		params = append(params, har.Param{Name: k, Value: fields[k]})
	}
	params = append(params, har.Param{Name: "file", FileName: fileName, ContentType: "application/octet-stream", Value: content})
	return b.add(req{method: "POST", url: "/api/upload_chunk", reqMime: "multipart/form-data; boundary=xyz",
		params: params, respMime: "application/json", respBody: mustJSON(fxOK)})
}

func TestChunkedUploadDetected(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("login").login(fxUser, fxPassword).endStep()
	b.step("upload big file", typed("Folder", "upload-path", "#upload-path", "text", "/public")).click("Upload")
	b.chunk(map[string]string{"path": "/public", "offset": "0", "total": "12"}, "big.bin", "AAAA")
	b.chunk(map[string]string{"path": "/public", "offset": "4", "total": "12"}, "big.bin", "BBBB")
	b.chunk(map[string]string{"path": "/public", "offset": "8", "total": "12"}, "big.bin", "CCCC")
	s := mustAnalyze(t, Options{}, b.build())

	tl := toolByName(t, s, "upload_big_file")
	if tl.File == nil || tl.File.Chunked == nil {
		t.Fatalf("file op = %+v", tl.File)
	}
	want := spec.Chunking{OffsetField: "offset", TotalField: "total", ChunkSize: 4}
	if *tl.File.Chunked != want {
		t.Fatalf("chunking = %+v, want %+v", *tl.File.Chunked, want)
	}
	for _, in := range tl.Inputs {
		if in.Field == "offset" || in.Field == "total" {
			t.Errorf("chunk field %s must be filled by the server, not an input", in.Field)
		}
	}
	if tl.Review {
		t.Errorf("unexpected review %q", tl.ReviewNotes)
	}
	inputByName(t, tl, "local_path")
	inputByName(t, tl, "path")

	t.Run("unrecognized", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("upload big file").click("Upload")
		b.chunk(map[string]string{"seq": "5", "path": "/public"}, "blob", "AAAAAA")
		b.chunk(map[string]string{"seq": "9", "path": "/public"}, "blob", "BB")
		b.chunk(map[string]string{"seq": "2", "path": "/public"}, "blob", "CCCC")
		s := mustAnalyze(t, Options{}, b.build())
		tl := toolByName(t, s, "upload_big_file")
		if tl.File == nil || tl.File.Direction != "upload" || tl.File.Chunked != nil {
			t.Fatalf("file op = %+v", tl.File)
		}
		if !tl.Review || !strings.Contains(strings.Join(tl.ReviewNotes, " "), "chunk") {
			t.Fatalf("want a review note about chunking, got review=%v %q", tl.Review, tl.ReviewNotes)
		}
	})

	t.Run("unequal chunks", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("upload big file").click("Upload")
		b.chunk(map[string]string{"offset": "0", "total": "9"}, "big.bin", "AAAA")
		b.chunk(map[string]string{"offset": "4", "total": "9"}, "big.bin", "BB")
		b.chunk(map[string]string{"offset": "6", "total": "9"}, "big.bin", "CCC")
		s := mustAnalyze(t, Options{}, b.build())
		tl := toolByName(t, s, "upload_big_file")
		if tl.File.Chunked != nil || !tl.Review {
			t.Fatalf("unequal chunks must be flagged, not guessed: %+v review=%v", tl.File, tl.Review)
		}
	})
}

func TestPrimaryOperationGetsLabel(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("login").login(fxUser, fxPassword).endStep()
	b.sysinfoPoll()
	b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks)
	b.sysinfoPoll().endStep()
	b.sysinfoPoll()
	s := mustAnalyze(t, Options{}, b.build())

	if got := toolByKey(t, s, "POST /api.php act=getdisklist").Name; got != "list_disks" {
		t.Fatalf("getdisklist named %q", got)
	}
	if got := toolByKey(t, s, "POST /api.php act=getsysinfo").Name; got != "getsysinfo" {
		t.Fatalf("background poll named %q", got)
	}
	tl := toolByName(t, s, "list_disks")
	want := "List disks. Calls POST /api.php (act=getdisklist). Recorded from the 'Disks' control."
	if tl.Description != want {
		t.Fatalf("description = %q\nwant          %q", tl.Description, want)
	}
	if got := toolByName(t, s, "getsysinfo").Description; got != "Calls POST /api.php (act=getsysinfo)." {
		t.Fatalf("background description = %q", got)
	}
}

func TestStepPrimaryRules(t *testing.T) {
	t.Run("first non-read wins", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("list shares").click("Shares").api("getsharelist", nil, fxOK).endStep()
		// The UI refreshes the list after adding: both requests follow the click.
		b.step("add share", typed("Name", "n", "#n", "text", "media")).click("Add").
			api("addshare", map[string]any{"name": "media"}, fxOK).api("getsharelist", nil, fxOK).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		if got := toolByKey(t, s, "POST /api.php act=getsharelist").Name; got != "list_shares" {
			t.Errorf("getsharelist named %q", got)
		}
		if got := toolByKey(t, s, "POST /api.php act=addshare").Name; got != "add_share" {
			t.Errorf("addshare named %q", got)
		}
	})
	t.Run("poll that follows a click by chance", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("add share", typed("Name", "n", "#n", "text", "media")).click("Add").
			api("addshare", map[string]any{"name": "media"}, fxOK)
		b.click("Add").sysinfoPoll().endStep() // the 5 s poll lands within 2 s of the click
		b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks)
		b.sysinfoPoll().endStep()
		s := mustAnalyze(t, Options{}, b.build())
		if got := toolByKey(t, s, "POST /api.php act=getsysinfo").Name; got != "getsysinfo" {
			t.Errorf("poll named %q", got)
		}
		toolByName(t, s, "add_share")
		toolByName(t, s, "list_disks")
	})
	t.Run("clicked list also loaded on its own", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.api("getsharelist", nil, fxOK) // the page loads the list after login
		b.step("list shares").click("Shares").api("getsharelist", nil, fxOK).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		if got := toolByKey(t, s, "POST /api.php act=getsharelist").Name; got != "list_shares" {
			t.Errorf("getsharelist named %q", got)
		}
	})
	t.Run("rest get label suffix", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("show info").click("Info").api("getsysinfo", nil, fxSysinfo)
		b.click("Info").api("getnetinfo", nil, fxOK).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		toolByName(t, s, "show_info")
		toolByName(t, s, "show_info_getnetinfo")
	})
	t.Run("login step leftovers are not named login", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword)
		b.click("Log in").api("getsysinfo", nil, fxSysinfo).endStep()
		b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		if got := toolByKey(t, s, "POST /api.php act=getsysinfo").Name; got != "getsysinfo" {
			t.Errorf("getsysinfo named %q", got)
		}
		toolByName(t, s, "list_disks")
	})
}

func TestToolNameSanitizing(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("login").login(fxUser, fxPassword).endStep()
	b.step("🔥 Reboot!!").click("Reboot").api("reboot", nil, fxOK).endStep()
	b.step("").click("Fan").api("getfan", nil, fxOK).endStep()
	b.step("type").click("Type").api("settype", map[string]any{"t": 1}, fxOK).endStep()
	b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks).endStep()
	b.step("list disks").click("Disks").api("getdiskinfo", nil, fxDisks).endStep()
	b.step("Ünïcode Shares").click("Shares").api("getsharelist", nil, fxOK).endStep()
	b.step("2fa setup").click("Setup").api("set2fa", map[string]any{"on": true}, fxOK).endStep()
	b.step("show info").click("Info").api("getsysinfo", nil, fxSysinfo)
	b.click("Info").get("/api/v1/net/info", fxOK).endStep()
	s := mustAnalyze(t, Options{}, b.build())

	want := map[string]string{
		"POST /api.php act=reboot":       "reboot",
		"POST /api.php act=getfan":       "getfan",
		"POST /api.php act=settype":      "type_op",
		"POST /api.php act=getdisklist":  "list_disks",
		"POST /api.php act=getdiskinfo":  "list_disks_2",
		"POST /api.php act=getsharelist": "unicode_shares",
		"POST /api.php act=set2fa":       "x_2fa_setup",
		"POST /api.php act=getsysinfo":   "show_info",
		"GET /api/v1/net/info":           "show_info_info",
	}
	for key, name := range want {
		if got := toolByKey(t, s, key).Name; got != name {
			t.Errorf("%s: name = %q, want %q", key, got, name)
		}
	}
	nameRE := regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	seen := map[string]bool{}
	for _, tl := range s.Tools {
		if !nameRE.MatchString(tl.Name) || seen[tl.Name] || spec.GoKeywords[tl.Name] {
			t.Errorf("bad or duplicate name %q", tl.Name)
		}
		seen[tl.Name] = true
	}
}

func TestSchemaInference(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("login").login(fxUser, fxPassword).endStep()
	b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks).endStep()
	b.step("list disks").click("Disks").api("getdisklist", nil, map[string]any{"ok": true, "data": []any{
		map[string]any{"id": "sdc", "model": "IronWolf", "size_gb": 8000, "health": "warning", "temp_c": 41.5},
	}}).endStep()
	b.step("about").click("About").api("getsysinfo", nil, map[string]any{"ok": true, "data": map[string]any{
		"model": "F4-424", "token": "tok-9f8e7d6c5b4a", "echo": fxCSRF,
	}}).endStep()
	s := mustAnalyze(t, Options{}, b.build())

	tl := toolByKey(t, s, "POST /api.php act=getdisklist")
	sc := tl.Response.Schema
	if sc["type"] != "object" {
		t.Fatalf("schema = %v", sc)
	}
	props := sc["properties"].(map[string]any)
	if props["ok"].(map[string]any)["type"] != "boolean" {
		t.Fatalf("ok = %v", props["ok"])
	}
	data := props["data"].(map[string]any)
	if data["type"] != "array" {
		t.Fatalf("data = %v", data)
	}
	items := data["items"].(map[string]any)
	if items["type"] != "object" {
		t.Fatalf("items = %v", items)
	}
	ip := items["properties"].(map[string]any)
	for field, typ := range map[string]string{"id": "string", "model": "string", "size_gb": "integer", "health": "string", "temp_c": "number"} {
		if got := ip[field].(map[string]any)["type"]; got != typ {
			t.Errorf("items.%s type = %v, want %s", field, got, typ)
		}
	}
	if tl.Response.ContentType != "application/json" || tl.Response.Example == nil {
		t.Fatalf("response = %+v", tl.Response)
	}

	about := toolByName(t, s, "about")
	data2 := about.Response.Example.(map[string]any)["data"].(map[string]any)
	if data2["token"] != har.Redacted || data2["echo"] != har.Redacted || data2["model"] != "F4-424" {
		t.Fatalf("example not redacted: %v", data2)
	}
}

func TestNoSecretsInSpec(t *testing.T) {
	for name, b := range map[string]*harBuilder{
		"recording": fakenasRecording(),
		"scrambled": fakenasScrambledRecording(),
	} {
		t.Run(name, func(t *testing.T) {
			h := b.build()
			s := mustAnalyze(t, Options{}, h)
			y := specYAML(t, s)
			for _, secret := range []string{fxPassword, fxSession, fxCSRF, "NASSESSID=" + fxSession} {
				if strings.Contains(y, secret) {
					t.Errorf("spec YAML contains %q:\n%s", secret, y)
				}
			}
		})
	}
	t.Run("password in a tool body", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("change password", typed("Old", "old", "#old", "password", fxPassword), typed("New", "new", "#new", "password", "n3w-Secret!")).
			click("Save").api("setpasswd", map[string]any{"old": fxPassword, "new": "n3w-Secret!", "note": "pw " + fxPassword}, fxOK).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		y := specYAML(t, s)
		for _, secret := range []string{fxPassword, "n3w-Secret!"} {
			if strings.Contains(y, secret) {
				t.Errorf("spec YAML contains %q:\n%s", secret, y)
			}
		}
		tl := toolByName(t, s, "change_password")
		inputByName(t, tl, "old")
		inputByName(t, tl, "new")
	})
}

func TestMergeOnReanalyze(t *testing.T) {
	first := newHAR(fxBase + "/")
	first.step("login").login(fxUser, fxPassword).endStep()
	first.step("list disks").click("Disks").api("getdisklist", nil, fxDisks).endStep()
	first.step("add share", typed("Share name", "share-name", "#share-name", "text", "media")).
		click("Add share").api("addshare", map[string]any{"name": "media"}, fxOK).endStep()
	existing := mustAnalyze(t, Options{Name: "nas"}, first.build())

	// The user renames a tool and rewrites a description by hand.
	toolByName(t, existing, "list_disks").Name = "get_disks"
	toolByName(t, existing, "add_share").Description = "Create a shared folder."
	p := filepath.Join(t.TempDir(), "nas.spec.yaml")
	if err := spec.Save(p, existing); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.Load(p)
	if err != nil {
		t.Fatal(err)
	}

	fresh := mustAnalyze(t, Options{Name: "nas"}, fakenasRecording().build())
	merged := spec.Merge(loaded, fresh)
	if err := merged.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := toolByKey(t, merged, "POST /api.php act=getdisklist").Name; got != "get_disks" {
		t.Fatalf("rename lost: %q", got)
	}
	if got := toolByKey(t, merged, "POST /api.php act=addshare").Description; got != "Create a shared folder." {
		t.Fatalf("description edit lost: %q", got)
	}
	toolByName(t, merged, "reboot")
	toolByName(t, merged, "delete_share")
	for _, tl := range merged.Tools {
		if tl.Name == "list_disks" {
			t.Fatal("the renamed tool came back under its old name")
		}
	}
}

func TestFakenasRecordingTools(t *testing.T) {
	s := mustAnalyze(t, Options{Name: "nas"}, fakenasRecording().build())
	if s.Service.Name != "nas" {
		t.Fatalf("service = %+v", s.Service)
	}
	want := map[string]string{
		"getsysinfo":    "read",
		"list_disks":    "read",
		"add_share":     "change",
		"upload_file":   "change",
		"download_file": "read",
		"delete_share":  "destructive",
		"reboot":        "destructive",
	}
	if len(s.Tools) != len(want) {
		t.Errorf("tools = %v", toolNames(s))
	}
	for name, kind := range want {
		tl := toolByName(t, s, name)
		if tl.Kind != kind || !tl.Enabled {
			t.Errorf("%s: kind %s enabled %v", name, tl.Kind, tl.Enabled)
		}
		if !reflect.DeepEqual(tl.Generated, spec.GeneratedHashes(tl)) {
			t.Errorf("%s: Generated = %v", name, tl.Generated)
		}
	}
	if s.AuthGenerated != spec.FieldHash(s.Auth) {
		t.Errorf("AuthGenerated = %q", s.AuthGenerated)
	}
	if got := toolByName(t, s, "reboot").Inputs; len(got) != 0 {
		t.Errorf("reboot inputs = %+v", got)
	}
	ls := toolByName(t, s, "list_disks")
	if !reflect.DeepEqual(ls.Source.Steps, []string{"list disks"}) || ls.Source.Trigger != "Disks" || ls.Source.Samples != 1 {
		t.Errorf("source = %+v", ls.Source)
	}
}

func TestAnalyzeSaveLoadRoundTrip(t *testing.T) {
	for name, b := range map[string]*harBuilder{
		"recording": fakenasRecording(),
		"scrambled": fakenasScrambledRecording(),
	} {
		t.Run(name, func(t *testing.T) {
			s := mustAnalyze(t, Options{}, b.build())
			p := filepath.Join(t.TempDir(), "s.spec.yaml")
			if err := spec.Save(p, s); err != nil {
				t.Fatal(err)
			}
			got, err := spec.Load(p)
			if err != nil {
				t.Fatalf("spec written by analyze does not load: %v", err)
			}
			for i := range got.Tools {
				if !reflect.DeepEqual(got.Tools[i].Generated, spec.GeneratedHashes(&got.Tools[i])) {
					t.Errorf("%s: hashes change across save and load", got.Tools[i].Name)
				}
			}
			if got.AuthGenerated != spec.FieldHash(got.Auth) {
				t.Errorf("auth hash changes across save and load")
			}
		})
	}
}

func TestAnalyzeIsDeterministic(t *testing.T) {
	a := specYAML(t, mustAnalyze(t, Options{}, fakenasRecording().build()))
	for i := 0; i < 5; i++ {
		if b := specYAML(t, mustAnalyze(t, Options{}, fakenasRecording().build())); b != a {
			t.Fatalf("output differs between runs:\n%s\n---\n%s", a, b)
		}
	}
}

func TestAnalyzeMultipleHARs(t *testing.T) {
	second := newHAR(fxBase + "/")
	second.step("login").login(fxUser, fxPassword)
	second.click("Log in").api("getquota", nil, fxOK).endStep() // the page loads it right after the login
	second.step("list shares").click("Shares").api("getsharelist", nil, map[string]any{"ok": true, "data": []any{"public"}}).endStep()
	s := mustAnalyze(t, Options{}, fakenasRecording().build(), second.build())
	toolByName(t, s, "list_shares")
	toolByName(t, s, "list_disks")
	if got := toolByKey(t, s, "POST /api.php act=getquota").Name; got != "getquota" {
		t.Errorf("a request in the second recording's login step is named %q", got)
	}
	if s.Auth.Mode != "http" {
		t.Fatalf("mode = %q", s.Auth.Mode)
	}
}

func TestOptions(t *testing.T) {
	t.Run("hosts", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks).endStep()
		b.add(req{method: "GET", url: "http://10.0.0.9:8080/api/status", respMime: "application/json", respBody: `{"up":true}`})
		s := mustAnalyze(t, Options{Hosts: []string{"10.0.0.9:8080"}}, b.build())
		if len(s.Tools) != 1 || s.Tools[0].Request.Path != "/api/status" {
			t.Fatalf("tools = %v", toolNames(s))
		}
		if !reflect.DeepEqual(s.Service.Hosts, []string{"10.0.0.9:8080"}) || s.Service.BaseURL != "http://10.0.0.9:8080" {
			t.Fatalf("service = %+v", s.Service)
		}
	})
	t.Run("most common xhr host without start url", func(t *testing.T) {
		b := newDevToolsHAR("http://nas.local:5000")
		b.add(req{method: "GET", url: "https://cdn.example.com/lib.js", respMime: "application/javascript", respBody: "x", resourceType: "script"})
		b.api("getdisklist", nil, fxDisks)
		b.api("getsysinfo", nil, fxSysinfo)
		b.add(req{method: "POST", url: "https://telemetry.example.com/v1", reqMime: "application/json", reqBody: "{}", respMime: "application/json", respBody: "{}"})
		s := mustAnalyze(t, Options{}, b.build())
		if s.Service.Name != "nas" || s.Service.BaseURL != "http://nas.local:5000" {
			t.Fatalf("service = %+v", s.Service)
		}
		if len(s.Tools) != 2 {
			t.Fatalf("tools = %v", toolNames(s))
		}
	})
	t.Run("bad name", func(t *testing.T) {
		if _, err := Analyze([]*har.HAR{fakenasRecording().build()}, Options{Name: "My NAS"}); err == nil || !strings.Contains(err.Error(), "my_nas") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestAnalyzeErrors(t *testing.T) {
	if _, err := Analyze(nil, Options{}); err == nil {
		t.Fatal("no HARs: want error")
	}
	b := newHAR(fxBase + "/")
	b.static()
	_, err := Analyze([]*har.HAR{b.build()}, Options{})
	if err == nil || !strings.Contains(err.Error(), "--host") {
		t.Fatalf("static-only HAR: err = %v", err)
	}
}

func TestDeriveName(t *testing.T) {
	for host, want := range map[string]string{
		"nas.local":              "nas",
		"NAS.local:5443":         "nas",
		"tos-nas.home.arpa":      "tos_nas",
		"www.router.example.com": "router",
		"192.168.1.10":           "device",
		"192.168.1.10:8080":      "device",
		"[fe80::1]:443":          "device",
		"::1":                    "device",
		"localhost":              "device",
		"localhost:8080":         "device",
		"":                       "device",
		"3dprinter.lan":          "x_3dprinter",
		"a-very-long-hostname-for-a-solar-inverter-on-the-roof.lan": "a_very_long_hostname_for_a_solar",
	} {
		if got := DeriveName(host); got != want {
			t.Errorf("DeriveName(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestAuthVariants(t *testing.T) {
	t.Run("classic form post login", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login")
		b.h.Log.Har2mcp.Login = &har.LoginCapture{PageURL: fxBase + "/login.html#top", UsernameSelector: "input[name=user]",
			PasswordSelector: "input[name=pass]", SubmitSelector: "form button", Username: fxUser, Password: fxPassword}
		b.click("Sign in").add(req{method: "POST", url: "/login.cgi", reqMime: "application/x-www-form-urlencoded",
			reqBody: "user=admin&pass=" + fxPassword + "&remember=1", status: 302, respMime: "text/html", resourceType: "document",
			setCookies: []har.Cookie{{Name: "SID", Value: "s3ss10n-77aa"}}})
		b.endStep()
		b.cookie, b.csrf = "", ""
		b.step("status").click("Status").add(req{method: "GET", url: "/cgi-bin/status.cgi?cmd=getstatus",
			headers: []har.NameValue{{Name: "Cookie", Value: "SID=s3ss10n-77aa"}}, respMime: "application/json", respBody: `{"up":true}`}).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		l := s.Auth.Login
		if s.Auth.Mode != "http" || l.Request.Path != "/login.cgi" || l.Request.BodyType != "form" {
			t.Fatalf("auth = %+v", s.Auth)
		}
		want := map[string]any{"user": "{{username}}", "pass": "{{password}}", "remember": "1"}
		if !reflect.DeepEqual(l.Request.Body, want) {
			t.Fatalf("login body = %v", l.Request.Body)
		}
		if l.PageURL != "/login.html#top" {
			t.Fatalf("page_url = %q", l.PageURL)
		}
		if !reflect.DeepEqual(s.Auth.Session.Cookies, []string{"SID"}) {
			t.Fatalf("cookies = %q", s.Auth.Session.Cookies)
		}
		tl := toolByName(t, s, "status")
		if tl.Request.Query["cmd"] != "getstatus" || tl.Request.Discriminator != "cmd" {
			t.Fatalf("status tool = %+v", tl.Request)
		}
		if strings.Contains(specYAML(t, s), "s3ss10n-77aa") {
			t.Fatal("session id in spec")
		}
	})

	t.Run("bearer token", func(t *testing.T) {
		const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
		b := newHAR("https://hub.local/")
		b.step("login", typed("Email", "email", "#email", "email", "me@example.com"), typed("Password", "password", "#pw", "password", fxPassword))
		b.click("Sign in").post("/api/v2/auth", map[string]any{"email": "me@example.com", "password": fxPassword},
			map[string]any{"access_token": jwt, "expires_in": 3600}).endStep()
		auth := []har.NameValue{{Name: "Authorization", Value: "Bearer " + jwt}}
		b.step("list devices").click("Devices").add(req{method: "GET", url: "/api/v2/devices", headers: auth,
			respMime: "application/json", respBody: `[{"id":1,"name":"plug"}]`}).endStep()
		b.step("turn on").click("On").add(req{method: "PUT", url: "/api/v2/devices/1/state", headers: auth,
			reqMime: "application/json", reqBody: `{"on":true}`, respMime: "application/json", respBody: `{"ok":true}`}).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		if s.Auth.Mode != "http" || s.Auth.Login.Request.Body["email"] != "{{username}}" {
			t.Fatalf("auth = %+v login %+v", s.Auth, s.Auth.Login)
		}
		// No login capture: the form comes from the typed inputs.
		if f := s.Auth.Login.Form; f == nil || f.Username != "#email" || f.Password != "#pw" {
			t.Fatalf("form = %+v", s.Auth.Login.Form)
		}
		if len(s.Auth.Session.Tokens) != 1 {
			t.Fatalf("tokens = %+v", s.Auth.Session.Tokens)
		}
		tf := s.Auth.Session.Tokens[0]
		if tf.From != (spec.TokenRef{ResponseJSON: "access_token"}) || tf.To != (spec.TokenRef{Header: "Authorization"}) || tf.Prefix != "Bearer " {
			t.Fatalf("token flow = %+v", tf)
		}
		// The prefix is in the spec, so it needs no review.
		if strings.Contains(strings.Join(s.Auth.ReviewNotes, " "), "Bearer") {
			t.Fatalf("unexpected note about the Bearer prefix: %q", s.Auth.ReviewNotes)
		}
		on := toolByName(t, s, "turn_on")
		if on.Kind != "change" || on.Request.Path != "/api/v2/devices/{id}/state" {
			t.Fatalf("turn_on = %+v", on)
		}
		if strings.Contains(specYAML(t, s), jwt) {
			t.Fatal("token in spec")
		}
	})

	t.Run("secret header with no source", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		key := []har.NameValue{{Name: "X-Api-Key", Value: "k3y-1234567890"}, {Name: "X-Requested-With", Value: "XMLHttpRequest"}}
		b.step("status").click("Status").add(req{method: "GET", url: "/api/status", headers: key, respMime: "application/json", respBody: `{"up":true}`}).endStep()
		b.step("reboot").click("Reboot").add(req{method: "POST", url: "/api/reboot", headers: key, reqMime: "application/json", reqBody: `{}`, respMime: "application/json", respBody: `{"ok":true}`}).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		if !s.Auth.Review || !strings.Contains(strings.Join(s.Auth.ReviewNotes, " "), "X-Api-Key") {
			t.Fatalf("auth = %+v", s.Auth)
		}
		tl := toolByName(t, s, "status")
		if !reflect.DeepEqual(tl.Request.Headers, map[string]string{"X-Requested-With": "XMLHttpRequest"}) {
			t.Fatalf("headers = %v", tl.Request.Headers)
		}
		if strings.Contains(specYAML(t, s), "k3y-1234567890") {
			t.Fatal("API key in spec")
		}
	})

	t.Run("exact password match beats a substring", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.add(req{method: "POST", url: "/api/telemetry", reqMime: "application/json", reqBody: `{"note":"xx` + fxPassword + `yy"}`, respMime: "application/json", respBody: `{}`})
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		if s.Auth.Login.Request.Path != "/api/login" {
			t.Fatalf("login = %+v", s.Auth.Login.Request)
		}
	})
}

func TestRequestShapes(t *testing.T) {
	b := newHAR(fxBase + "/")
	form := func(body string) req {
		return req{method: "POST", url: "/cgi-bin/luci", reqMime: "application/x-www-form-urlencoded", reqBody: body,
			respMime: "application/json", respBody: `{"ok":true}`}
	}
	b.step("led on").click("On").add(form("cmd=setled&state=on")).endStep()
	b.step("led off").click("Off").add(form("cmd=setled&state=off")).endStep()
	gql := func(id int, on bool) req {
		return req{method: "POST", url: "/graphql", reqMime: "application/json",
			reqBody:  mustJSON(map[string]any{"operationName": "SetLight", "query": "mutation SetLight($id:Int!,$on:Boolean!){setLight(id:$id,on:$on){ok}}", "variables": map[string]any{"id": id, "on": on}}),
			respMime: "application/json", respBody: `{"data":{"setLight":{"ok":true}}}`}
	}
	b.step("light").click("Light 3").add(gql(3, true))
	b.click("Light 4").add(gql(4, false)).endStep()
	b.step("soap").click("Go").add(req{method: "POST", url: "/upnp/control", reqMime: "text/xml", reqBody: "<s:Envelope/>",
		respMime: "text/xml", respBody: `<?xml version="1.0"?><r>ok</r>`}).endStep()
	b.step("bulk").click("Go").add(req{method: "POST", url: "/api/bulk", reqMime: "application/json", reqBody: `[1,2]`,
		respMime: "application/json", respBody: `{"ok":true}`}).endStep()
	b.step("keys").click("Key").get("/api/users/12/keys/34", fxOK)
	b.click("Key").get("/api/users/13/keys/35", fxOK).endStep()
	const boundary = "XyZ"
	b.step("raw upload").click("Upload").add(req{method: "POST", url: "/api/raw_upload", reqMime: "multipart/form-data; boundary=" + boundary,
		reqBody: "--" + boundary + "\r\nContent-Disposition: form-data; name=\"dir\"\r\n\r\n/media\r\n--" + boundary +
			"\r\nContent-Disposition: form-data; name=\"upfile\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\nabc\r\n--" + boundary + "--\r\n",
		respMime: "application/json", respBody: `{"ok":true}`}).endStep()
	s := mustAnalyze(t, Options{}, b.build())

	led := toolByKey(t, s, "POST /cgi-bin/luci cmd=setled")
	if led.Request.BodyType != "form" || led.Request.Body["cmd"] != "setled" {
		t.Fatalf("led = %+v", led.Request)
	}
	if in := inputByName(t, led, "state"); in.Type != "string" || in.In != "body" || !in.Required {
		t.Fatalf("state = %+v", in)
	}

	light := toolByKey(t, s, "POST /graphql operationName=SetLight")
	if q, _ := light.Request.Body["query"].(string); !strings.HasPrefix(q, "mutation SetLight") {
		t.Fatalf("query should stay fixed: %v", light.Request.Body)
	}
	if in := inputByName(t, light, "id"); in.Type != "integer" || in.Field != "variables.id" {
		t.Fatalf("id = %+v", in)
	}
	if in := inputByName(t, light, "on"); in.Type != "boolean" || in.Field != "variables.on" {
		t.Fatalf("on = %+v", in)
	}

	soap := toolByName(t, s, "soap")
	if !soap.Review || soap.Request.BodyType != "none" || !strings.Contains(strings.Join(soap.ReviewNotes, " "), "text/xml") {
		t.Fatalf("soap = %+v %q", soap.Request, soap.ReviewNotes)
	}
	if ex, _ := soap.Response.Example.(string); !strings.Contains(ex, "<r>ok</r>") || soap.Response.Schema != nil {
		t.Fatalf("soap response = %+v", soap.Response)
	}
	if bulk := toolByName(t, s, "bulk"); !bulk.Review || !strings.Contains(strings.Join(bulk.ReviewNotes, " "), "array") {
		t.Fatalf("bulk = %+v", bulk)
	}

	keys := toolByKey(t, s, "GET /api/users/{user_id}/keys/{key_id}")
	inputByName(t, keys, "user_id")
	inputByName(t, keys, "key_id")

	raw := toolByName(t, s, "raw_upload")
	if raw.File == nil || raw.File.Part != "upfile" {
		t.Fatalf("raw upload = %+v", raw.File)
	}
	if in := inputByName(t, raw, "dir"); in.In != "body" || !in.Required {
		t.Fatalf("dir = %+v", in)
	}
}

func TestInputNamesStayValid(t *testing.T) {
	long := strings.Repeat("a", 64)
	taken := map[string]bool{}
	first := inputName("x."+long, taken)
	second := inputName("y."+long, taken)
	re := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	if first == second || !re.MatchString(first) || !re.MatchString(second) {
		t.Fatalf("names %q and %q", first, second)
	}
	if got := inputName("share-name", map[string]bool{}); got != "share_name" {
		t.Fatalf("share-name -> %q", got)
	}
	if got := inputName("filter.shareName", map[string]bool{}); got != "shareName" {
		t.Fatalf("filter.shareName -> %q", got)
	}
}

func TestUniqueInputStaysWithinLimit(t *testing.T) {
	long := strings.Repeat("b", 64)
	taken := map[string]bool{long: true}
	got := uniqueInput(long, taken)
	if len(got) > 64 || got == long || !taken[got] {
		t.Fatalf("uniqueInput = %q (%d chars)", got, len(got))
	}
}

func TestAnalyzeOddEntries(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.add(req{method: "GET", url: "data:image/png;base64,AAAA"})
	b.add(req{method: "GET", url: "/ws", status: 101, resourceType: "websocket"})
	b.add(req{method: "POST", url: "/api/failed", reqMime: "application/json", reqBody: `{"a":1}`, failed: true})
	b.add(req{method: "POST", url: "/api/broken", reqMime: "application/json", reqBody: `{"a":`, respMime: "application/json", respBody: `{"ok":true}`})
	b.add(req{method: "GET", url: "/api/huge", respMime: "application/json"})
	b.h.Log.Entries[len(b.h.Log.Entries)-1].Response.Content.Truncated = true
	b.add(req{method: "GET", url: "/api/blob", respMime: "application/octet-stream", respBody: "\xff\xfe\x00binary"})
	b.add(req{method: "PUT", url: "/api/firmware", reqMime: "application/json", respMime: "application/json", respBody: `{"ok":true}`})
	b.h.Log.Entries[len(b.h.Log.Entries)-1].Request.PostData = &har.PostData{MimeType: "application/json", Truncated: true}
	b.add(req{method: "HEAD", url: "/api/ping/"})
	b.add(req{method: "GET", url: "/api/search?tag=a&tag=b&q=x", respMime: "application/json", respBody: `[]`})
	b.add(req{method: "POST", url: "/", reqMime: "application/json", reqBody: `{"method":"System.Info","params":{},"id":1}`, respMime: "application/json", respBody: `{"result":{}}`})
	b.add(req{method: "POST", url: "/", reqMime: "application/json", reqBody: `{"method":"System.Info","params":{},"id":2}`, respMime: "application/json", respBody: `{"result":null}`})
	b.add(req{method: "PUT", url: "/api/cfg", reqMime: "application/json", reqBody: `{"a":{"b":{"c":[1,2]}},"e":{}}`, respMime: "text/plain", respBody: "saved"})
	b.add(req{method: "GET", url: "/api/%7Bweird%7D/x%20y", respMime: "application/json", respBody: `{}`})
	s := mustAnalyze(t, Options{}, b.build())

	rpc := toolByKey(t, s, "POST / method=System.Info")
	if rpc.Name != "system_info" {
		t.Errorf("JSON-RPC tool named %q", rpc.Name)
	}
	if in := inputByName(t, rpc, "id"); in.Type != "integer" {
		t.Errorf("JSON-RPC id = %+v", in)
	}
	if blob := toolByKey(t, s, "GET /api/blob"); blob.File == nil || blob.File.Direction != "download" {
		t.Errorf("binary response should be a download: %+v", blob.File)
	}
	if failed := toolByKey(t, s, "POST /api/failed"); !strings.Contains(strings.Join(failed.ReviewNotes, " "), "no successful response was recorded (status 0)") {
		t.Errorf("a call that never succeeded should be flagged: %q", failed.ReviewNotes)
	}
	if fw := toolByKey(t, s, "PUT /api/firmware"); !fw.Review || !strings.Contains(strings.Join(fw.ReviewNotes, " "), "recording cap") {
		t.Errorf("a request body dropped by the recording cap should be flagged: %+v %q", fw.Request, fw.ReviewNotes)
	}
	if cfg := toolByKey(t, s, "PUT /api/cfg"); cfg.Response.Example != "saved" || cfg.Kind != "change" {
		t.Errorf("cfg = %+v", cfg)
	}
	search := toolByKey(t, s, "GET /api/search")
	if search.Request.Query["q"] != "x" || !reflect.DeepEqual(search.Request.Query["tag"], []any{"a", "b"}) {
		t.Errorf("search query = %v", search.Request.Query)
	}
	for _, tl := range s.Tools {
		if strings.Contains(tl.Request.Path, "{weird}") {
			t.Errorf("literal braces in a path must stay escaped: %s", tl.Request.Path)
		}
		if strings.HasPrefix(tl.Request.Path, "/ws") {
			t.Errorf("WebSocket upgrade became a tool")
		}
	}
}

func TestWifiKeyIsNeverAnExample(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("login").login(fxUser, fxPassword).endStep()
	b.step("set wifi", typed("Network", "ssid", "#ssid", "text", "HomeNet"), typed("Key", "psk", "#psk", "text", "correct-horse-42")).
		click("Save").api("setwifi", map[string]any{"ssid": "HomeNet", "psk": "correct-horse-42"}, fxOK).endStep()
	s := mustAnalyze(t, Options{}, b.build())
	tl := toolByName(t, s, "set_wifi")
	if in := inputByName(t, tl, "psk"); in.Example != nil || !in.Required {
		t.Fatalf("psk = %+v", in)
	}
	if in := inputByName(t, tl, "ssid"); in.Example != "HomeNet" {
		t.Fatalf("ssid = %+v", in)
	}
	if strings.Contains(specYAML(t, s), "correct-horse-42") {
		t.Fatal("Wi-Fi key in spec")
	}
}
