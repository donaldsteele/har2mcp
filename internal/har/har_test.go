package har

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sampleHAR() *HAR {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	exp := t0.Add(24 * time.Hour)
	return &HAR{Log: Log{
		Version: "1.2",
		Creator: Creator{Name: "har2mcp", Version: "test"},
		Entries: []Entry{
			{
				StartedDateTime: t0.Add(time.Second),
				Time:            12.5,
				Request: Request{
					Method:      "POST",
					URL:         "http://nas.local/api/login?next=%2Fhome&pw=hunter2-nas",
					HTTPVersion: "HTTP/1.1",
					Headers: []NameValue{
						{Name: "Content-Type", Value: "application/json"},
						{Name: "Referer", Value: "http://nas.local/?p=hunter2-nas"},
					},
					QueryString: []NameValue{{Name: "next", Value: "/home"}, {Name: "pw", Value: "hunter2-nas"}},
					PostData: &PostData{
						MimeType: "application/json",
						Text:     `{"username":"admin","password":"hunter2-nas"}`,
					},
					HeadersSize: -1,
					BodySize:    46,
				},
				Response: Response{
					Status:      200,
					StatusText:  "OK",
					HTTPVersion: "HTTP/1.1",
					Cookies:     []Cookie{{Name: "NASSESSID", Value: "abc123def", Path: "/", HTTPOnly: true, Expires: &exp}},
					Headers: []NameValue{
						{Name: "Set-Cookie", Value: "NASSESSID=abc123def; HttpOnly; Path=/"},
						{Name: "Content-Type", Value: "application/json"},
					},
					Content: Content{
						Size:     44,
						MimeType: "application/json",
						Text:     `{"ok":true,"data":{"token":"csrf-tok-777"}}`,
					},
					HeadersSize: -1,
					BodySize:    44,
				},
				Timings: Timings{Send: 1, Wait: 10, Receive: 1.5},
				Step:    "login",
				Trigger: &Trigger{Text: "Sign in", Role: "button", Selector: "#login"},
			},
			{
				StartedDateTime: t0.Add(2 * time.Second),
				Time:            8,
				Request: Request{
					Method:      "POST",
					URL:         "http://nas.local/api.php",
					HTTPVersion: "HTTP/1.1",
					Cookies:     []Cookie{{Name: "NASSESSID", Value: "abc123def"}},
					Headers: []NameValue{
						{Name: "Cookie", Value: "NASSESSID=abc123def"},
						{Name: "X-Csrf-Token", Value: "csrf-tok-777"},
						{Name: "Authorization", Value: "Bearer bearer-secret-1"},
						{Name: "X-Session-Id", Value: "sess-42"},
						{Name: "X-Requested-With", Value: "XMLHttpRequest"},
					},
					PostData: &PostData{
						MimeType: "application/json",
						Text:     `{"act":"getdisklist","nested":{"Pwd":"p1","list":[{"TOKEN":"t2"}]},"lang":"en"}`,
					},
				},
				Response: Response{
					Status:      200,
					StatusText:  "OK",
					HTTPVersion: "HTTP/1.1",
					Content: Content{
						Size:      3000000,
						MimeType:  "application/json",
						Truncated: true,
					},
				},
				Step:    "list disks",
				Trigger: &Trigger{Text: "Disks", AriaLabel: "Show disks", Role: "button", Selector: "#btn-disks"},
			},
			{
				StartedDateTime: t0.Add(3 * time.Second),
				Request: Request{
					Method: "PUT", URL: "http://nas.local/api/chunk", HTTPVersion: "HTTP/1.1",
					PostData: &PostData{MimeType: "application/octet-stream", Truncated: true},
					BodySize: 4194304,
				},
				Response: Response{Status: 200},
			},
		},
		Har2mcp: &Meta{
			Version:  "test",
			StartURL: "http://nas.local/",
			Steps: []Step{
				{
					Name:  "list disks",
					Start: t0,
					End:   t0.Add(5 * time.Second),
					Inputs: []TypedInput{
						{Label: "Share name", Name: "share", Selector: "#share-name", Type: "text", Value: "media"},
						{Label: "Password", Name: "pw", Selector: "#password", Type: "password", Value: "hunter2-nas"},
					},
				},
			},
			Login: &LoginCapture{
				PageURL:          "http://nas.local/",
				UsernameSelector: "#username",
				PasswordSelector: "#password",
				SubmitSelector:   "#login",
				Username:         "admin",
				Password:         "hunter2-nas",
			},
		},
	}}
}

func TestRoundTripPreservesExtensions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.har")
	if err := Save(path, sampleHAR()); err != nil {
		t.Fatal(err)
	}
	h, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if h.Log.Har2mcp == nil || len(h.Log.Har2mcp.Steps) == 0 || h.Log.Har2mcp.Steps[0].Name != "list disks" {
		t.Fatalf("steps not preserved: %+v", h.Log.Har2mcp)
	}
	if h.Log.Entries[0].Step != "login" || h.Log.Entries[1].Step != "list disks" {
		t.Fatalf("_step not preserved: %q %q", h.Log.Entries[0].Step, h.Log.Entries[1].Step)
	}
	if h.Log.Entries[1].Trigger == nil || h.Log.Entries[1].Trigger.Text != "Disks" {
		t.Fatalf("_trigger not preserved: %+v", h.Log.Entries[1].Trigger)
	}
	if !h.Log.Entries[1].Response.Content.Truncated {
		t.Fatal("_truncated not preserved")
	}
	if pd := h.Log.Entries[2].Request.PostData; pd == nil || !pd.Truncated {
		t.Fatalf("request _truncated not preserved: %+v", pd)
	}
	if got := h.Log.Har2mcp.Login.PasswordSelector; got != "#password" {
		t.Fatalf("login selector = %q", got)
	}
	if !reflect.DeepEqual(h.Log.Har2mcp.Steps[0].Inputs, sampleHAR().Log.Har2mcp.Steps[0].Inputs) {
		t.Fatalf("typed inputs changed: %+v", h.Log.Har2mcp.Steps[0].Inputs)
	}
	if !h.Log.Entries[0].StartedDateTime.Equal(sampleHAR().Log.Entries[0].StartedDateTime) {
		t.Fatalf("startedDateTime changed: %v", h.Log.Entries[0].StartedDateTime)
	}
}

func TestSavedJSONUsesHARFieldNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.har")
	h := sampleHAR()
	h.Log.Entries[1].Request.QueryString = nil // nil slices must still be written as []
	if err := Save(path, h); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"log": {`, `"startedDateTime"`, `"httpVersion"`, `"postData"`, `"mimeType"`,
		`"headersSize"`, `"bodySize"`, `"redirectURL"`, `"httpOnly": true`, `"queryString": []`,
		`"cache": {}`, `"_har2mcp"`, `"startUrl"`, `"_step": "login"`, `"_trigger"`, `"ariaLabel"`,
		`"_truncated": true`, `"passwordSelector"`, `?next=%2Fhome&pw=`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("saved HAR lacks %s", want)
		}
	}
	if strings.Contains(s, "null") {
		t.Errorf("saved HAR contains null:\n%s", s)
	}
	if !strings.HasPrefix(s, "{\n  \"log\"") {
		t.Errorf("saved HAR is not indented with 2 spaces: %.40q", s)
	}
}

func TestSaveMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not POSIX on Windows")
	}
	path := filepath.Join(t.TempDir(), "s.har")
	// A pre-existing world-readable file must end up 0600 too.
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, sampleHAR()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

const devtoolsHAR = "\ufeff" + `{
  "log": {
    "version": "1.2",
    "creator": {"name": "WebInspector", "version": "537.36"},
    "pages": [{"startedDateTime": "2026-11-21T10:00:00.000Z", "id": "page_1", "title": "NAS", "pageTimings": {"onContentLoad": 120.5, "onLoad": 300}}],
    "entries": [
      {
        "_initiator": {"type": "script", "stack": {"callFrames": []}},
        "_priority": "High",
        "_resourceType": "xhr",
        "cache": {},
        "connection": "443",
        "pageref": "page_1",
        "request": {
          "method": "POST",
          "url": "https://nas.local/api.php",
          "httpVersion": "http/2.0",
          "headers": [{"name": ":authority", "value": "nas.local"}, {"name": "content-type", "value": "application/json"}],
          "queryString": [],
          "cookies": [],
          "headersSize": -1,
          "bodySize": 20,
          "postData": {"mimeType": "application/json", "text": "{\"act\":\"getdisklist\"}"}
        },
        "response": {
          "status": 200,
          "statusText": "",
          "httpVersion": "http/2.0",
          "headers": [{"name": "content-type", "value": "application/json"}],
          "cookies": [{"name": "x", "value": "y", "expires": null, "httpOnly": false, "secure": true}, {"name": "z", "value": "w", "expires": "Infinity"}],
          "content": {"size": 11, "mimeType": "application/json", "compression": 0, "text": "eyJvayI6dHJ1ZX0=", "encoding": "base64"},
          "redirectURL": "",
          "headersSize": -1,
          "bodySize": -1,
          "_transferSize": 120,
          "_error": null
        },
        "serverIPAddress": "192.168.1.10",
        "startedDateTime": "2026-11-21T10:00:01.123Z",
        "time": 35.2,
        "timings": {"blocked": 1.1, "dns": -1, "ssl": -1, "connect": -1, "send": 0.2, "wait": 30.1, "receive": 3.8, "_blocked_queueing": 0.5}
      }
    ]
  }
}`

func TestLoadDevToolsExport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devtools.har")
	if err := os.WriteFile(path, []byte(devtoolsHAR), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Log.Entries) != 1 {
		t.Fatalf("entries = %d", len(h.Log.Entries))
	}
	e := h.Log.Entries[0]
	if e.ResourceType != "xhr" {
		t.Fatalf("_resourceType = %q", e.ResourceType)
	}
	if e.Request.PostData == nil || e.Request.PostData.Text != `{"act":"getdisklist"}` {
		t.Fatalf("postData = %+v", e.Request.PostData)
	}
	b, err := e.Response.Content.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"ok":true}` {
		t.Fatalf("Bytes() = %q", b)
	}
	if e.Request.Header("Content-Type") != "application/json" {
		t.Fatalf("case-insensitive header lookup failed")
	}
	if e.Response.Header("X-Missing") != "" {
		t.Fatal("missing header should be empty")
	}
	if len(e.Response.Cookies) != 2 || e.Response.Cookies[0].Expires != nil || e.Response.Cookies[1].Expires != nil {
		t.Fatalf("cookie expiry not tolerated: %+v", e.Response.Cookies)
	}
	if !e.Response.Cookies[0].Secure {
		t.Fatal("cookie secure flag lost")
	}
	if e.Timings.Wait != 30.1 || h.Log.Har2mcp != nil {
		t.Fatalf("timings/meta wrong: %+v %+v", e.Timings, h.Log.Har2mcp)
	}
	if len(h.Log.Pages) != 1 || h.Log.Pages[0].ID != "page_1" {
		t.Fatalf("pages = %+v", h.Log.Pages)
	}
}

func TestLoadRejectsNonHAR(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"spec.yaml":  "har2mcp: 1\nservice:\n  name: nas\n",
		"other.json": `{"hello":"world"}`,
		"empty.har":  "",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("Load(%s) succeeded, want error", name)
		}
	}
	if _, err := Load(filepath.Join(dir, "missing.har")); err == nil {
		t.Error("Load of a missing file succeeded")
	}
}

func TestContentBytes(t *testing.T) {
	plain := Content{Text: "hello"}
	if b, err := plain.Bytes(); err != nil || string(b) != "hello" {
		t.Fatalf("plain Bytes() = %q, %v", b, err)
	}
	raw := Content{Text: base64.RawStdEncoding.EncodeToString([]byte("\x00\x01binary")), Encoding: "base64"}
	if b, err := raw.Bytes(); err != nil || string(b) != "\x00\x01binary" {
		t.Fatalf("unpadded base64 Bytes() = %q, %v", b, err)
	}
	if _, err := (Content{Text: "!!!", Encoding: "base64"}).Bytes(); err == nil {
		t.Fatal("bad base64 should fail")
	}
	if _, err := (Content{Text: "x", Encoding: "rot13"}).Bytes(); err == nil {
		t.Fatal("unknown encoding should fail")
	}
}

func headerValue(h []NameValue, name string) string {
	for _, nv := range h {
		if strings.EqualFold(nv.Name, name) {
			return nv.Value
		}
	}
	return "<missing>"
}

func TestRedact(t *testing.T) {
	in := sampleHAR()
	before, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := Redact(in)
	after, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Redact modified its input")
	}
	if out == in {
		t.Fatal("Redact returned its input")
	}

	login, api := out.Log.Entries[0], out.Log.Entries[1]

	// Named sensitive headers.
	for _, c := range []struct {
		h    []NameValue
		name string
	}{
		{api.Request.Headers, "Cookie"},
		{login.Response.Headers, "Set-Cookie"},
		{api.Request.Headers, "Authorization"},
		{api.Request.Headers, "X-Csrf-Token"},
		{api.Request.Headers, "X-Session-Id"},
	} {
		if got := headerValue(c.h, c.name); got != Redacted {
			t.Errorf("header %s = %q, want %s", c.name, got, Redacted)
		}
	}
	if got := headerValue(api.Request.Headers, "X-Requested-With"); got != "XMLHttpRequest" {
		t.Errorf("harmless header changed: %q", got)
	}
	if got := headerValue(login.Request.Headers, "Content-Type"); got != "application/json" {
		t.Errorf("content-type changed: %q", got)
	}

	// Cookie values.
	if api.Request.Cookies[0].Value != Redacted || login.Response.Cookies[0].Value != Redacted {
		t.Errorf("cookie values not redacted: %+v %+v", api.Request.Cookies, login.Response.Cookies)
	}
	if api.Request.Cookies[0].Name != "NASSESSID" {
		t.Errorf("cookie name changed: %q", api.Request.Cookies[0].Name)
	}

	// Captured passwords.
	if out.Log.Har2mcp.Login.Password != Redacted {
		t.Errorf("login password = %q", out.Log.Har2mcp.Login.Password)
	}
	if out.Log.Har2mcp.Login.Username != "admin" {
		t.Errorf("login username changed: %q", out.Log.Har2mcp.Login.Username)
	}
	inputs := out.Log.Har2mcp.Steps[0].Inputs
	if inputs[1].Value != Redacted {
		t.Errorf("password typed input = %q", inputs[1].Value)
	}
	if inputs[0].Value != "media" {
		t.Errorf("non-password typed input changed: %q", inputs[0].Value)
	}

	// The login password anywhere in bodies, query strings and URLs.
	if strings.Contains(login.Request.URL, "hunter2-nas") {
		t.Errorf("password left in URL: %s", login.Request.URL)
	}
	if login.Request.QueryString[1].Value != Redacted {
		t.Errorf("password left in query string: %+v", login.Request.QueryString)
	}
	if login.Request.QueryString[0].Value != "/home" {
		t.Errorf("harmless query value changed: %+v", login.Request.QueryString)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(login.Request.PostData.Text), &body); err != nil {
		t.Fatalf("redacted login body is not JSON: %v", err)
	}
	if body["password"] != Redacted || body["username"] != "admin" {
		t.Errorf("login body = %v", body)
	}

	// JSON fields with secret names, any depth, any case.
	var apiBody map[string]any
	if err := json.Unmarshal([]byte(api.Request.PostData.Text), &apiBody); err != nil {
		t.Fatal(err)
	}
	nested := apiBody["nested"].(map[string]any)
	if nested["Pwd"] != Redacted {
		t.Errorf("nested Pwd = %v", nested["Pwd"])
	}
	if nested["list"].([]any)[0].(map[string]any)["TOKEN"] != Redacted {
		t.Errorf("nested TOKEN = %v", nested["list"])
	}
	if apiBody["act"] != "getdisklist" || apiBody["lang"] != "en" {
		t.Errorf("harmless fields changed: %v", apiBody)
	}
	var loginResp map[string]any
	if err := json.Unmarshal([]byte(login.Response.Content.Text), &loginResp); err != nil {
		t.Fatal(err)
	}
	if loginResp["data"].(map[string]any)["token"] != Redacted {
		t.Errorf("response token = %v", loginResp)
	}

	// Nothing secret survives anywhere in the serialized output.
	all, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hunter2-nas", "abc123def", "csrf-tok-777", "bearer-secret-1"} {
		if strings.Contains(string(all), secret) {
			t.Errorf("redacted HAR still contains %q", secret)
		}
	}
	if !api.Response.Content.Truncated || api.Step != "list disks" || api.Trigger.Text != "Disks" {
		t.Error("non-secret extension fields were lost")
	}
}

func TestRedactScrubsLeakedValues(t *testing.T) {
	in := sampleHAR()
	// The CSRF token from the login response is echoed in a later body under
	// an innocuous name, and the session id shows up in a Location header.
	in.Log.Entries[1].Request.PostData.Text = `{"act":"addshare","name":"media","x":"csrf-tok-777"}`
	in.Log.Entries[1].Response.Headers = []NameValue{{Name: "Location", Value: "/home?sid=abc123def"}}
	in.Log.Entries[1].Response.Content = Content{
		MimeType: "application/json",
		Text:     base64.StdEncoding.EncodeToString([]byte(`{"ok":true,"secret_token":"zzz-999-yyy","echo":"hunter2-nas"}`)),
		Encoding: "base64",
	}
	out := Redact(in)
	all, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hunter2-nas", "abc123def", "csrf-tok-777"} {
		if strings.Contains(string(all), secret) {
			t.Errorf("redacted HAR still contains %q", secret)
		}
	}
	b, err := out.Log.Entries[1].Response.Content.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "zzz-999-yyy") || strings.Contains(string(b), "hunter2-nas") {
		t.Errorf("base64 body not redacted: %s", b)
	}
	if !strings.Contains(out.Log.Entries[1].Request.PostData.Text, `"name":"media"`) {
		t.Errorf("unrelated body text changed: %s", out.Log.Entries[1].Request.PostData.Text)
	}
}

func TestRedactNil(t *testing.T) {
	if Redact(nil) != nil {
		t.Fatal("Redact(nil) should be nil")
	}
}
