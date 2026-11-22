package har

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// entry builds a minimal entry for the redact tests.
func entry(at time.Time, method, url, reqMime, reqBody string, headers []NameValue, respMime, respBody string) Entry {
	e := Entry{
		StartedDateTime: at,
		Request:         Request{Method: method, URL: url, HTTPVersion: "HTTP/1.1", Headers: headers},
		Response:        Response{Status: 200, HTTPVersion: "HTTP/1.1", Content: Content{MimeType: respMime, Text: respBody}},
	}
	if reqMime != "" {
		e.Request.PostData = &PostData{MimeType: reqMime, Text: reqBody}
	}
	if i := strings.IndexByte(url, '?'); i >= 0 {
		for _, pair := range strings.Split(url[i+1:], "&") {
			k, v, _ := strings.Cut(pair, "=")
			e.Request.QueryString = append(e.Request.QueryString, NameValue{Name: k, Value: v})
		}
	}
	return e
}

func marshalString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A router or camera that still uses admin/admin: the password is also an
// ordinary word in its paths, so it is removed only where a whole value
// equals it.
func TestRedactWeakPasswordKeepsPaths(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	h := &HAR{Log: Log{Version: "1.2", Entries: []Entry{
		entry(t0, "POST", "http://cam.local/admin/login", "application/json", `{"username":"admin","password":"admin"}`, nil,
			"application/json", `{"ok":true}`),
		entry(t0.Add(time.Second), "GET", "http://cam.local/admin/api/status?view=administrator&who=admin", "", "", nil,
			"application/json", `{"role":"administrator","model":"admin-cam"}`),
		entry(t0.Add(2*time.Second), "POST", "http://cam.local/admin/api/user", "application/x-www-form-urlencoded", "name=bob&group=administrators&old=admin", nil,
			"application/json", `{}`),
	}, Har2mcp: &Meta{StartURL: "http://cam.local/", Login: &LoginCapture{Username: "admin", Password: "admin"}}}}

	out := Redact(h)
	e := out.Log.Entries
	if e[0].Request.URL != "http://cam.local/admin/login" {
		t.Errorf("login URL = %q", e[0].Request.URL)
	}
	if e[1].Request.URL != "http://cam.local/admin/api/status?view=administrator&who=REDACTED" {
		t.Errorf("status URL = %q", e[1].Request.URL)
	}
	if e[1].Request.QueryString[0].Value != "administrator" || e[1].Request.QueryString[1].Value != Redacted {
		t.Errorf("query = %+v", e[1].Request.QueryString)
	}
	var login map[string]any
	if err := json.Unmarshal([]byte(e[0].Request.PostData.Text), &login); err != nil {
		t.Fatal(err)
	}
	if login["password"] != Redacted {
		t.Errorf("login body = %v", login)
	}
	if e[1].Response.Content.Text != `{"role":"administrator","model":"admin-cam"}` {
		t.Errorf("response = %s", e[1].Response.Content.Text)
	}
	if got := e[2].Request.PostData.Text; got != "name=bob&group=administrators&old=REDACTED" {
		t.Errorf("form body = %q", got)
	}
	if out.Log.Har2mcp.Login.Password != Redacted {
		t.Errorf("captured password = %q", out.Log.Har2mcp.Login.Password)
	}
}

// Redact uses the same secret names as analysis: sid, psk and the rest.
// A Fritz!Box-style session id comes back in an XML response and goes out
// in a form field named sid.
func TestRedactSharedSecretNames(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	const sid = "9a8b7c6d5e4f3a2b"
	h := &HAR{Log: Log{Version: "1.2", Entries: []Entry{
		entry(t0, "GET", "http://fritz.box/login_sid.lua?version=2", "", "", nil,
			"text/xml", `<?xml version="1.0"?><SessionInfo><SID>`+sid+`</SID><Challenge>2$60000$aa</Challenge></SessionInfo>`),
		entry(t0.Add(time.Second), "POST", "http://fritz.box/data.lua", "application/x-www-form-urlencoded", "xhr=1&sid="+sid+"&page=overview", nil,
			"application/json", `{"data":{"fritzos":{"nspver":"7.57"}}}`),
		entry(t0.Add(2*time.Second), "POST", "http://fritz.box/wlan.lua", "application/x-www-form-urlencoded", "ssid=HomeNet&psk=Sunflower-2026", nil,
			"application/json", `{"ok":true}`),
		entry(t0.Add(3*time.Second), "POST", "http://fritz.box/api.lua", "application/json", `{"pin":"482913","otp":"551234","access_key":"AKIAEXAMPLE7"}`, nil,
			"application/json", `{"ok":true}`),
	}}}
	all := marshalString(t, Redact(h))
	for _, secret := range []string{sid, "Sunflower-2026", "482913", "551234", "AKIAEXAMPLE7"} {
		if strings.Contains(all, secret) {
			t.Errorf("redacted HAR still contains %q", secret)
		}
	}
	if !strings.Contains(all, "HomeNet") || !strings.Contains(all, "page=overview") {
		t.Error("harmless values were removed")
	}
}

// A Wi-Fi key typed into a plain text field is a secret too.
func TestRedactTypedSecretInputs(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	h := &HAR{Log: Log{Version: "1.2", Entries: []Entry{
		entry(t0, "POST", "http://router.local/api/wifi", "application/json", `{"ssid":"HomeNet","key":"Sunflower-2026"}`, nil, "application/json", `{}`),
	}, Har2mcp: &Meta{Steps: []Step{{Name: "set wifi", Inputs: []TypedInput{
		{Label: "Network name", Name: "ssid", Type: "text", Value: "HomeNet"},
		{Label: "Wi-Fi password", Name: "key", Type: "text", Value: "Sunflower-2026"},
		{Label: "Admin PIN", Name: "adminPin", Type: "text", Value: "4829"},
	}}}}}}
	out := Redact(h)
	in := out.Log.Har2mcp.Steps[0].Inputs
	if in[0].Value != "HomeNet" || in[1].Value != Redacted || in[2].Value != Redacted {
		t.Errorf("typed inputs = %+v", in)
	}
	if strings.Contains(marshalString(t, out), "Sunflower-2026") {
		t.Error("Wi-Fi key left in the HAR")
	}
}

// Values a response handed out and later requests sent back in their path
// or a header are session tokens, whatever their field name: the OpenWrt
// LuCI ;stok=<token> path, a Hue bridge's /api/<username>/ path, a token from
// an XML response sent in a header.
func TestRedactTokensFromResponses(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	const (
		stok = "9f8e7d6c5b4a39281706"
		hue  = "1028d66426293e821ecfd9ef1a0731df"
		tok  = "TkN4bWZ2c1pq7Q1b"
	)
	h := &HAR{Log: Log{Version: "1.2", Entries: []Entry{
		entry(t0, "POST", "http://router.local/cgi-bin/luci/rpc/auth", "application/json", `{"method":"login"}`, nil,
			"application/json", `{"id":1,"result":{"key2":"`+stok+`"}}`),
		entry(t0.Add(time.Second), "GET", "http://router.local/cgi-bin/luci/;stok="+stok+"/admin/status", "", "", nil, "application/json", `{"up":true}`),
		entry(t0.Add(2*time.Second), "POST", "http://hue.local/api", "application/json", `{"devicetype":"app"}`, nil,
			"application/json", `[{"success":{"username":"`+hue+`"}}]`),
		entry(t0.Add(3*time.Second), "GET", "http://hue.local/api/"+hue+"/lights", "", "", nil, "application/json", `{"1":{"name":"Desk"}}`),
		entry(t0.Add(4*time.Second), "GET", "http://modem.local/api/webserver/token", "", "", nil,
			"text/xml", `<response><TokInfo>`+tok+`</TokInfo></response>`),
		entry(t0.Add(5*time.Second), "POST", "http://modem.local/api/sms/send", "text/xml", `<request><Phone>123</Phone></request>`,
			[]NameValue{{Name: "X-Req-V", Value: tok}}, "text/xml", `<response>OK</response>`),
		// An item picked from a list is not a token.
		entry(t0.Add(6*time.Second), "GET", "http://nas.local/api/disks", "", "", nil, "application/json", `{"disks":[{"id":"sda"},{"id":"disk-0001"}]}`),
		entry(t0.Add(7*time.Second), "POST", "http://nas.local/api/disk", "application/json", `{"id":"disk-0001"}`, nil, "application/json", `{}`),
	}}}
	out := Redact(h)
	all := marshalString(t, out)
	for _, secret := range []string{stok, hue, tok} {
		if strings.Contains(all, secret) {
			t.Errorf("redacted HAR still contains %q", secret)
		}
	}
	if got := out.Log.Entries[1].Request.URL; got != "http://router.local/cgi-bin/luci/;stok=REDACTED/admin/status" {
		t.Errorf("LuCI URL = %q", got)
	}
	if got := out.Log.Entries[7].Request.PostData.Text; got != `{"id":"disk-0001"}` {
		t.Errorf("item id was redacted: %s", got)
	}
}

func TestSecretRules(t *testing.T) {
	for _, c := range []struct {
		name string
		want bool
	}{
		{"password", true}, {"data.token", true}, {"sid", true}, {"stok", true}, {"psk", true}, {"pin", true},
		{"otp", true}, {"passphrase", true}, {"access_key", true}, {"private_key", true}, {"wpa_key", true},
		{"xsrf_token", true}, {"name", false}, {"size", false}, {"keyword", false},
	} {
		if got := IsSecretField(c.name); got != c.want {
			t.Errorf("IsSecretField(%q) = %v", c.name, got)
		}
	}
	for _, c := range []struct {
		in   TypedInput
		want bool
	}{
		{TypedInput{Type: "password"}, true},
		{TypedInput{Label: "Wi-Fi password", Name: "key", Type: "text"}, true},
		{TypedInput{Label: "WPA key", Type: "text"}, true},
		{TypedInput{Name: "wifiKey", Type: "text"}, true},
		{TypedInput{Label: "PIN", Type: "number"}, true},
		{TypedInput{Label: "Share name", Name: "share-name", Type: "text"}, false},
		{TypedInput{Label: "Monkey count", Name: "keyboard", Type: "text"}, false},
	} {
		if got := IsSecretInput(c.in); got != c.want {
			t.Errorf("IsSecretInput(%+v) = %v", c.in, got)
		}
	}
	for _, c := range []struct {
		v    string
		want bool
	}{
		{"admin", false}, {"1234", false}, {"password", false}, {"administrator", false}, {"admin123", false},
		{"hunter2", true}, {"hunter2-nas", true}, {"correcthorsebattery", true}, {"abcdef", false},
	} {
		if got := Distinctive(c.v); got != c.want {
			t.Errorf("Distinctive(%q) = %v", c.v, got)
		}
	}
	for _, h := range []string{"Cookie", "Set-Cookie", "Authorization", "X-XSRF-TOKEN", "X-Api-Key", "X-Session-Id"} {
		if !IsSecretHeader(h) {
			t.Errorf("IsSecretHeader(%q) = false", h)
		}
	}
}
