package inspect

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/har2mcp/internal/analyze"
	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

const (
	password = "hunter2-nas"
	session  = "abc123"
	csrf     = "csrf-7f3a9c2e1b44"
)

// recording builds a small fakenas recording: login, list disks, add share,
// upload and a background poll.
func recording() *har.HAR {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	h := &har.HAR{Log: har.Log{
		Version: "1.2",
		Creator: har.Creator{Name: "har2mcp", Version: "0.1.0"},
		Har2mcp: &har.Meta{
			Version:  "0.1.0",
			StartURL: "http://192.168.1.50/",
			Steps: []har.Step{
				{Name: "login", Start: at(1), End: at(2), Inputs: []har.TypedInput{
					{Label: "Username", Selector: "#username", Type: "text", Value: "admin"},
					{Label: "Password", Selector: "#password", Type: "password", Value: password},
				}},
				{Name: "list disks", Start: at(3), End: at(4)},
				{Name: "add share", Start: at(5), End: at(6), Inputs: []har.TypedInput{
					{Label: "Share name", Selector: "#share-name", Type: "text", Value: "media"},
				}},
				{Name: "upload file", Start: at(7), End: at(8)},
				{Name: "set fan", Start: at(9), End: at(10)},
			},
			Login: &har.LoginCapture{
				PageURL: "http://192.168.1.50/", UsernameSelector: "#username", PasswordSelector: "#password",
				SubmitSelector: "#login", Username: "admin", Password: password,
			},
		},
	}}
	jsonResp := func(v any) har.Response {
		b, _ := json.Marshal(v)
		return har.Response{Status: 200, Headers: []har.NameValue{{Name: "Content-Type", Value: "application/json"}},
			Content: har.Content{MimeType: "application/json", Text: string(b)}}
	}
	authed := []har.NameValue{{Name: "Cookie", Value: "NASSESSID=" + session}, {Name: "X-Csrf-Token", Value: csrf}}
	api := func(s float64, step, act string, extra map[string]any, trig string, resp any) har.Entry {
		body := map[string]any{"act": act}
		for k, v := range extra {
			body[k] = v
		}
		b, _ := json.Marshal(body)
		e := har.Entry{
			StartedDateTime: t0.Add(time.Duration(s * float64(time.Second))),
			Request: har.Request{Method: "POST", URL: "http://192.168.1.50/api.php", Headers: authed,
				Cookies:  []har.Cookie{{Name: "NASSESSID", Value: session}},
				PostData: &har.PostData{MimeType: "application/json", Text: string(b)}},
			Response: jsonResp(resp),
			Step:     step,
		}
		if trig != "" {
			e.Trigger = &har.Trigger{Text: trig}
		}
		return e
	}
	login := har.Entry{
		StartedDateTime: at(1).Add(500 * time.Millisecond),
		Request: har.Request{Method: "POST", URL: "http://192.168.1.50/api/login",
			PostData: &har.PostData{MimeType: "application/json", Text: `{"username":"admin","password":"` + password + `"}`}},
		Response: jsonResp(map[string]any{"ok": true, "data": map[string]any{"token": csrf}}),
		Step:     "login",
		Trigger:  &har.Trigger{Text: "Log in"},
	}
	login.Response.Headers = append(login.Response.Headers, har.NameValue{Name: "Set-Cookie", Value: "NASSESSID=" + session + "; HttpOnly; Path=/"})
	upload := har.Entry{
		StartedDateTime: at(7).Add(500 * time.Millisecond),
		Request: har.Request{Method: "POST", URL: "http://192.168.1.50/api/upload", Headers: authed,
			PostData: &har.PostData{MimeType: "multipart/form-data; boundary=x", Params: []har.Param{
				{Name: "path", Value: "/public"}, {Name: "file", FileName: "hello.txt", ContentType: "text/plain"},
			}}},
		Response: jsonResp(map[string]any{"ok": true}),
		Step:     "upload file",
		Trigger:  &har.Trigger{Text: "Upload"},
	}
	h.Log.Entries = []har.Entry{
		{StartedDateTime: at(0), Request: har.Request{Method: "GET", URL: "http://192.168.1.50/"}, ResourceType: "document",
			Response: har.Response{Status: 200, Content: har.Content{MimeType: "text/html", Text: "<html></html>"}}},
		login,
		api(2.5, "", "getsysinfo", nil, "", map[string]any{"ok": true}),
		api(3.5, "list disks", "getdisklist", nil, "Disks", map[string]any{"ok": true, "data": []any{"sda"}}),
		api(5.5, "add share", "addshare", map[string]any{"name": "media"}, "Add share", map[string]any{"ok": true}),
		upload,
		api(9.5, "set fan", "setfan", map[string]any{"speed": "high"}, "Fan", map[string]any{"ok": true}),
		api(11, "", "getsysinfo", nil, "", map[string]any{"ok": true}),
	}
	return h
}

func TestInspectSpecRedactedSummary(t *testing.T) {
	s, err := analyze.Analyze([]*har.HAR{recording()}, analyze.Options{Name: "nas"})
	if err != nil {
		t.Fatal(err)
	}
	// A careless hand edit put the password in the spec; inspect must still
	// not print it.
	s.Auth.Login.Request.Body["password"] = password
	s.Tools[0].Request.Headers = map[string]string{"X-Debug": password}
	s.Tools[0].Description = "uses " + password
	s.Auth.Session.Tokens = append(s.Auth.Session.Tokens, spec.TokenFlow{Name: "authorization",
		From: spec.TokenRef{ResponseJSON: "data.token"}, To: spec.TokenRef{Header: "Authorization"}, Prefix: "Bearer "})

	var buf bytes.Buffer
	if err := Spec(&buf, s); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	t.Log("\n" + out)
	for _, want := range []string{"nas", "NAS_URL", "Auth: http", "POST /api/login", "NASSESSID", "X-Csrf-Token", "data.token", `header Authorization, prefixed "Bearer "`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	lines := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 4 {
			lines[strings.Join(f[:4], " ")] = true
		}
	}
	for _, want := range []string{
		"read list_disks POST /api.php",
		"change add_share POST /api.php",
		"change upload_file POST /api/upload",
		"read getsysinfo POST /api.php",
		"change set_fan POST /api.php",
	} {
		if !lines[want] {
			t.Errorf("no tool line %q", want)
		}
	}
	if !strings.Contains(out, "upload_file") || !strings.Contains(out, `part "file"`) {
		t.Errorf("file tools missing")
	}
	if !strings.Contains(out, "set_fan") || !strings.Contains(out, `"speed"`) {
		t.Errorf("review flags missing")
	}
	for _, secret := range []string{password, session, csrf} {
		if strings.Contains(out, secret) {
			t.Errorf("output contains secret %q", secret)
		}
	}
}

func TestInspectSpecNoReview(t *testing.T) {
	s := &spec.Spec{Har2mcp: 1, Service: spec.Service{Name: "plug"}, Auth: spec.Auth{Mode: "none"},
		Tools: []spec.Tool{{Name: "status", Kind: "read", Enabled: false, Request: spec.Request{Method: "GET", Path: "/status"}}}}
	var buf bytes.Buffer
	if err := Spec(&buf, s); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Auth: none", "read", "status", "GET /status", "(disabled)", "nothing flagged", "0 enabled"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestInspectHAR(t *testing.T) {
	var buf bytes.Buffer
	if err := HAR(&buf, recording(), analyze.Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	t.Log("\n" + out)
	for _, want := range []string{"har2mcp recording", "8 requests", "192.168.1.50", "login", "list disks", "#password", "Auth: http", "list_disks"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	for _, secret := range []string{password, session, csrf, "admin"} {
		if strings.Contains(out, secret) {
			t.Errorf("output contains %q", secret)
		}
	}
}

func TestInspectPlainHAR(t *testing.T) {
	h := recording()
	h.Log.Har2mcp = nil
	h.Log.Creator = har.Creator{Name: "WebInspector", Version: "537.36"}
	var buf bytes.Buffer
	if err := HAR(&buf, h, analyze.Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "plain HAR") || !strings.Contains(out, "review") {
		t.Errorf("output:\n%s", out)
	}
	if strings.Contains(out, password) {
		t.Error("output contains the password")
	}
}

func TestInspectHARAnalysisError(t *testing.T) {
	h := &har.HAR{Log: har.Log{Version: "1.2", Entries: []har.Entry{{
		Request:  har.Request{Method: "GET", URL: "http://192.168.1.50/logo.png"},
		Response: har.Response{Status: 200, Content: har.Content{MimeType: "image/png"}},
	}}}}
	var buf bytes.Buffer
	err := HAR(&buf, h, analyze.Options{})
	if err == nil {
		t.Fatal("want the analysis error")
	}
	if !strings.Contains(buf.String(), "1 request") {
		t.Errorf("the HAR summary should still be printed:\n%s", buf.String())
	}
}
