package analyze

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// Tests for the issues found in the independent review of v0.1.0.

func notes(a []string) string { return strings.Join(a, "\n") }

// loginStep records a login step with typed values, the recorder's login
// capture and the login request.
func (b *harBuilder) loginStep(user, password string, r req) *harBuilder {
	b.step("login", typed("Username", "username", "#u", "text", user), typed("Password", "password", "#p", "password", password))
	b.h.Log.Har2mcp.Login = &har.LoginCapture{PageURL: b.base + "/", UsernameSelector: "#u", PasswordSelector: "#p",
		SubmitSelector: "#go", Username: user, Password: password}
	return b.click("Log in").add(r).endStep()
}

func cookieHeader(v string) []har.NameValue { return []har.NameValue{{Name: "Cookie", Value: v}} }

// A camera that still uses admin/admin: the password is an ordinary word in
// its paths and values, so the spec keeps those and the login still maps
// the username and password.
func TestWeakPasswordDoesNotMangleSpec(t *testing.T) {
	b := newHAR("http://cam.local/")
	b.loginStep("admin", "admin", req{method: "POST", url: "/admin/login", reqMime: "application/json",
		reqBody: `{"username":"admin","password":"admin"}`, respMime: "application/json", respBody: `{"ok":true}`,
		setCookies: []har.Cookie{{Name: "CAMSESS", Value: "s3ss-0001-abcd"}}})
	ck := cookieHeader("CAMSESS=s3ss-0001-abcd")
	b.step("camera status").click("Status").add(req{method: "GET", url: "/admin/api/status?view=administrator", headers: ck,
		respMime: "application/json", respBody: `{"role":"administrator","model":"cam-2"}`}).endStep()
	b.step("set name", typed("Name", "name", "#name", "text", "porch")).click("Save").add(req{method: "POST", url: "/admin/api/name",
		headers: ck, reqMime: "application/json", reqBody: `{"name":"porch","group":"admin"}`, respMime: "application/json", respBody: `{"ok":true}`}).endStep()
	s := mustAnalyze(t, Options{}, b.build())

	l := s.Auth.Login
	if s.Auth.Mode != "http" || l.Request.Path != "/admin/login" {
		t.Fatalf("auth = %+v", s.Auth)
	}
	if l.Request.Body["username"] != "{{username}}" || l.Request.Body["password"] != "{{password}}" {
		t.Fatalf("login body = %v", l.Request.Body)
	}
	st := toolByName(t, s, "camera_status")
	if st.Request.Path != "/admin/api/status" || st.Request.Query["view"] != "administrator" {
		t.Fatalf("status request = %+v", st.Request)
	}
	if sn := toolByName(t, s, "set_name"); sn.Request.Body["group"] != "admin" {
		t.Fatalf("set_name body = %v", sn.Request.Body)
	}
	y := specYAML(t, s)
	if strings.Contains(y, "/REDACTED") || strings.Contains(y, "REDACTEDistrator") {
		t.Fatalf("the spec was mangled:\n%s", y)
	}
	if !strings.Contains(notes(s.Auth.ReviewNotes), "common") {
		t.Errorf("want a note that the password is short or common, got %q", s.Auth.ReviewNotes)
	}
}

// When the username equals the password, the field name decides which
// placeholder a login field gets.
func TestLoginUsernameEqualsPassword(t *testing.T) {
	b := newHAR("http://cam.local/")
	b.loginStep("admin", "admin", req{method: "POST", url: "/login.cgi", reqMime: "application/x-www-form-urlencoded",
		reqBody: "pwd=admin&usr=admin", respMime: "application/json", respBody: `{"ok":true}`,
		setCookies: []har.Cookie{{Name: "SID", Value: "s3ss-0001-abcd"}}})
	b.step("status").click("Status").add(req{method: "GET", url: "/status.cgi", headers: cookieHeader("SID=s3ss-0001-abcd"),
		respMime: "application/json", respBody: `{"up":true}`}).endStep()
	s := mustAnalyze(t, Options{}, b.build())
	if body := s.Auth.Login.Request.Body; body["usr"] != "{{username}}" || body["pwd"] != "{{password}}" {
		t.Fatalf("login body = %v", body)
	}
}

// The device redirects from the typed http port to https on another port.
// The server must use the origin the API ran on.
func TestBaseURLIsWhereTheAPIRan(t *testing.T) {
	b := newHAR("http://hub.local:8181/")
	b.add(req{method: "GET", url: "http://hub.local:8181/", status: 302, resourceType: "document", respMime: "text/html",
		respHeaders: []har.NameValue{{Name: "Location", Value: "https://hub.local:5443/"}}})
	b.h.Log.Entries[0].Response.RedirectURL = "https://hub.local:5443/"
	b.base = "https://hub.local:5443"
	b.static()
	b.step("login").login(fxUser, fxPassword).endStep()
	b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks).endStep()
	s := mustAnalyze(t, Options{}, b.build())
	if s.Service.BaseURL != "https://hub.local:5443" {
		t.Fatalf("base_url = %q, want the origin of the API", s.Service.BaseURL)
	}
}

// The start host redirects to another host (tplinkwifi.net -> 192.168.0.1).
func TestHostsFollowTheStartRedirect(t *testing.T) {
	b := newHAR("http://tplinkwifi.net/")
	b.add(req{method: "GET", url: "http://tplinkwifi.net/", status: 302, resourceType: "document", respMime: "text/html",
		respHeaders: []har.NameValue{{Name: "Location", Value: "http://192.168.0.1/"}}})
	b.h.Log.Entries[0].Response.RedirectURL = "http://192.168.0.1/"
	b.base = "http://192.168.0.1"
	b.static()
	b.step("login").login(fxUser, fxPassword).endStep()
	b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks).endStep()
	s := mustAnalyze(t, Options{}, b.build())
	if s.Service.BaseURL != "http://192.168.0.1" || !contains(s.Service.Hosts, "192.168.0.1") {
		t.Fatalf("service = %+v", s.Service)
	}
	toolByName(t, s, "list_disks")

	t.Run("script redirect", func(t *testing.T) {
		b := newHAR("http://tplinkwifi.net/")
		b.add(req{method: "GET", url: "http://tplinkwifi.net/", resourceType: "document", respMime: "text/html",
			respBody: `<script>location.href="http://192.168.0.1/"</script>`})
		b.base = "http://192.168.0.1"
		b.static()
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("list disks").click("Disks").api("getdisklist", nil, fxDisks).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		if s.Service.BaseURL != "http://192.168.0.1" {
			t.Fatalf("service = %+v", s.Service)
		}
		toolByName(t, s, "list_disks")
	})
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Without a submit selector, the generated browser login presses Enter;
// the spec says so.
func TestBrowserLoginWithoutSubmitSelector(t *testing.T) {
	h := fakenasScrambledRecording().build()
	h.Log.Har2mcp.Login.SubmitSelector = ""
	s := mustAnalyze(t, Options{}, h)
	if s.Auth.Mode != "browser" || s.Auth.Login.Form.Submit != "" {
		t.Fatalf("auth = %+v", s.Auth)
	}
	if !s.Auth.Review || !strings.Contains(notes(s.Auth.ReviewNotes), "Enter") {
		t.Fatalf("want a note about pressing Enter, got %q", s.Auth.ReviewNotes)
	}
}

// A CSRF token from a response other than the login's: the spec records the
// request that returns it, so the server can make it after logging in.
func TestTokenFromAnotherResponse(t *testing.T) {
	const csrf = "c5rf-77aa-91bb"
	b := newHAR(fxBase + "/")
	b.loginStep(fxUser, fxPassword, req{method: "POST", url: "/api/login", reqMime: "application/json",
		reqBody: mustJSON(map[string]any{"username": fxUser, "password": fxPassword}), respMime: "application/json",
		respBody: `{"ok":true}`, setCookies: []har.Cookie{{Name: "NASSESSID", Value: fxSession}}})
	ck := cookieHeader("NASSESSID=" + fxSession)
	b.add(req{method: "GET", url: "/api/session", headers: ck, respMime: "application/json", respBody: `{"user":"admin","csrfToken":"` + csrf + `"}`})
	withToken := append(cookieHeader("NASSESSID="+fxSession), har.NameValue{Name: "X-CSRF-Token", Value: csrf})
	b.step("list disks").click("Disks").add(req{method: "POST", url: "/api.php", headers: withToken, reqMime: "application/json",
		reqBody: `{"act":"getdisklist"}`, respMime: "application/json", respBody: mustJSON(fxDisks)}).endStep()
	b.step("add share", typed("Share name", "name", "#n", "text", "media")).click("Add").add(req{method: "POST", url: "/api.php",
		headers: withToken, reqMime: "application/json", reqBody: `{"act":"addshare","name":"media"}`, respMime: "application/json",
		respBody: `{"ok":true}`}).endStep()
	s := mustAnalyze(t, Options{}, b.build())

	if len(s.Auth.Session.Tokens) != 1 {
		t.Fatalf("tokens = %+v", s.Auth.Session.Tokens)
	}
	tf := s.Auth.Session.Tokens[0]
	if tf.From != (spec.TokenRef{ResponseJSON: "csrfToken"}) || tf.To != (spec.TokenRef{Header: "X-CSRF-Token"}) {
		t.Fatalf("token flow = %+v", tf)
	}
	if tf.Request == nil || tf.Request.Method != "GET" || tf.Request.Path != "/api/session" {
		t.Fatalf("token request = %+v", tf.Request)
	}
	if !s.Auth.Review || !strings.Contains(notes(s.Auth.ReviewNotes), "/api/session") {
		t.Fatalf("want a review note naming /api/session, got %q", s.Auth.ReviewNotes)
	}
	if strings.Contains(specYAML(t, s), csrf) {
		t.Fatal("token in spec")
	}
}

// A plain HAR with a password change or "add user" request but no login: no
// login is guessed, and the operation stays a tool.
func TestGuessedLoginNeedsAStrongSignal(t *testing.T) {
	t.Run("password change", func(t *testing.T) {
		b := newDevToolsHAR(fxBase)
		b.post("/api/user/update", map[string]any{"user": "admin", "old_password": fxPassword, "new_password": "N3w-pass-2026"}, fxOK)
		b.api("getdisklist", nil, fxDisks)
		s := mustAnalyze(t, Options{}, b.build())
		if s.Auth.Mode != "none" || s.Auth.Login != nil {
			t.Fatalf("auth = %+v", s.Auth)
		}
		tl := toolByKey(t, s, "POST /api/user/update")
		for _, name := range []string{"old_password", "new_password"} {
			if in := inputByName(t, tl, name); in.Example != nil {
				t.Errorf("%s has an example: %+v", name, in)
			}
		}
		y := specYAML(t, s)
		if strings.Contains(y, fxPassword) || strings.Contains(y, "N3w-pass-2026") {
			t.Fatal("password in spec")
		}
	})
	t.Run("add user", func(t *testing.T) {
		b := newDevToolsHAR(fxBase)
		b.post("/api/users/create", map[string]any{"name": "bob", "password": "B0b-pass-77"}, fxOK)
		b.api("getdisklist", nil, fxDisks)
		s := mustAnalyze(t, Options{}, b.build())
		if s.Auth.Mode != "none" {
			t.Fatalf("auth = %+v", s.Auth)
		}
		toolByKey(t, s, "POST /api/users/create")
		if !strings.Contains(notes(s.Auth.ReviewNotes), "/api/users/create") {
			t.Errorf("want a note naming the request that was not taken as the login, got %q", s.Auth.ReviewNotes)
		}
	})
	// A login-like path does not make a password change or a sign-up a
	// login: replaying either at every login would reset the password or
	// add accounts.
	for _, path := range []string{"/cgi-bin/auth/changepw", "/api/auth/register", "/api/session/reset_password"} {
		t.Run("change on an auth path "+path, func(t *testing.T) {
			b := newDevToolsHAR(fxBase)
			b.post(path, map[string]any{"user": "admin", "password": "N3w-pass-2026"}, map[string]any{"ok": true, "token": "t0k3n-abcdef12"})
			b.api("getdisklist", nil, fxDisks)
			s := mustAnalyze(t, Options{}, b.build())
			if s.Auth.Mode != "none" || s.Auth.Login != nil {
				t.Fatalf("auth = %+v", s.Auth)
			}
			toolByKey(t, s, "POST "+path)
			if !strings.Contains(notes(s.Auth.ReviewNotes), path) {
				t.Errorf("want a note naming %s, got %q", path, s.Auth.ReviewNotes)
			}
		})
	}
	t.Run("a real login is still found", func(t *testing.T) {
		b := newDevToolsHAR(fxBase)
		b.post("/cgi-bin/auth", map[string]any{"user": "admin", "pass": fxPassword}, map[string]any{"ok": true, "token": "t0k3n-abcdef12"})
		b.api("getdisklist", nil, fxDisks)
		s := mustAnalyze(t, Options{}, b.build())
		if s.Auth.Mode != "http" || s.Auth.Login.Request.Path != "/cgi-bin/auth" {
			t.Fatalf("auth = %+v", s.Auth)
		}
	})
	t.Run("a login under a users path is still found", func(t *testing.T) {
		b := newDevToolsHAR(fxBase)
		b.post("/api/users/login", map[string]any{"username": "admin", "password": fxPassword}, map[string]any{"ok": true, "token": "t0k3n-abcdef12"})
		b.api("getdisklist", nil, fxDisks)
		s := mustAnalyze(t, Options{}, b.build())
		if s.Auth.Mode != "http" || s.Auth.Login.Request.Path != "/api/users/login" {
			t.Fatalf("auth = %+v", s.Auth)
		}
	})
}

// IP cameras, printers and UPS cards often use HTTP Basic auth.
func TestBasicAuth(t *testing.T) {
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:Sunflower-2026"))
	b := newHAR("http://cam.local/")
	b.add(req{method: "GET", url: "/", status: 401, resourceType: "document", respMime: "text/html", respBody: "Unauthorized",
		respHeaders: []har.NameValue{{Name: "WWW-Authenticate", Value: `Basic realm="cam"`}}})
	auth := []har.NameValue{{Name: "Authorization", Value: basic}}
	b.step("camera info").click("Info").add(req{method: "GET", url: "/cgi-bin/info.cgi?cmd=getinfo", headers: auth,
		respMime: "application/json", respBody: `{"model":"cam-2"}`}).endStep()
	b.step("reboot").click("Reboot").add(req{method: "POST", url: "/cgi-bin/reboot.cgi", headers: auth,
		reqMime: "application/x-www-form-urlencoded", reqBody: "now=1", respMime: "application/json", respBody: `{"ok":true}`}).endStep()
	s := mustAnalyze(t, Options{}, b.build())
	if s.Auth.Mode != "basic" || s.Auth.Login != nil || len(s.Auth.ReloginOn) != 0 {
		t.Fatalf("auth = %+v", s.Auth)
	}
	y := specYAML(t, s)
	if strings.Contains(y, "Sunflower-2026") || strings.Contains(y, basic[6:]) {
		t.Fatal("credentials in spec")
	}

	t.Run("digest", func(t *testing.T) {
		b := newHAR("http://printer.local/")
		auth := []har.NameValue{{Name: "Authorization", Value: `Digest username="admin", realm="p", nonce="abc", uri="/status", response="0123456789abcdef"`}}
		b.step("status").click("Status").add(req{method: "GET", url: "/api/status", headers: auth, respMime: "application/json", respBody: `{"ok":true}`}).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		if s.Auth.Mode != "none" || !strings.Contains(notes(s.Auth.ReviewNotes), "Digest") {
			t.Fatalf("auth = %+v", s.Auth)
		}
	})
}

// chunkNoBytes posts one chunk the way Chrome records it: the file part has
// no bytes, and the body size counts them.
func (b *harBuilder) chunkNoBytes(fields map[string]string, fileName string, size int) *harBuilder {
	var params []har.Param
	text := ""
	for _, k := range sortedKeys(fields) {
		params = append(params, har.Param{Name: k, Value: fields[k]})
		text += "--xyz\r\nContent-Disposition: form-data; name=\"" + k + "\"\r\n\r\n" + fields[k] + "\r\n"
	}
	params = append(params, har.Param{Name: "file", FileName: fileName, ContentType: "application/octet-stream"})
	text += "--xyz\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + fileName + "\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n--xyz--\r\n"
	b.add(req{method: "POST", url: "/api/upload_chunk", reqMime: "multipart/form-data; boundary=xyz", reqBody: text,
		params: params, respMime: "application/json", respBody: mustJSON(fxOK)})
	b.h.Log.Entries[len(b.h.Log.Entries)-1].Request.BodySize = int64(len(text) + size)
	return b
}

func TestChunkedUploadIndexBaseAndSize(t *testing.T) {
	t.Run("index starts at 1", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("upload big file").click("Upload")
		b.chunk(map[string]string{"path": "/public", "resumableChunkNumber": "1", "resumableTotalSize": "10"}, "big.bin", "AAAA")
		b.chunk(map[string]string{"path": "/public", "resumableChunkNumber": "2", "resumableTotalSize": "10"}, "big.bin", "BBBB")
		b.chunk(map[string]string{"path": "/public", "resumableChunkNumber": "3", "resumableTotalSize": "10"}, "big.bin", "CC")
		s := mustAnalyze(t, Options{}, b.build())
		c := toolByName(t, s, "upload_big_file").File.Chunked
		want := spec.Chunking{IndexField: "resumableChunkNumber", TotalField: "resumableTotalSize", ChunkSize: 4, IndexBase: 1}
		if c == nil || *c != want {
			t.Fatalf("chunking = %+v, want %+v", c, want)
		}
	})
	t.Run("size from a protocol field", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("upload big file").click("Upload")
		for i, n := range []int{4, 4, 2} {
			b.chunkNoBytes(map[string]string{"dzchunkindex": string(rune('0' + i)), "dzchunksize": "4", "dztotalfilesize": "10"}, "big.bin", n)
		}
		h := b.build()
		for i := range h.Log.Entries {
			h.Log.Entries[i].Request.BodySize = 0 // the size comes from dzchunksize alone
		}
		s := mustAnalyze(t, Options{}, h)
		c := toolByName(t, s, "upload_big_file").File.Chunked
		want := spec.Chunking{IndexField: "dzchunkindex", TotalField: "dztotalfilesize", ChunkSize: 4}
		if c == nil || *c != want {
			t.Fatalf("chunking = %+v, want %+v", c, want)
		}
	})
	t.Run("size from the body size", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("upload big file").click("Upload")
		for i, n := range []int{8, 8, 3} {
			b.chunkNoBytes(map[string]string{"index": string(rune('0' + i)), "path": "/public"}, "big.bin", n)
		}
		s := mustAnalyze(t, Options{}, b.build())
		c := toolByName(t, s, "upload_big_file").File.Chunked
		if c == nil || c.ChunkSize != 8 || c.IndexField != "index" {
			t.Fatalf("chunking = %+v", c)
		}
	})
}

// jQuery and ExtJS add cache-busting query parameters. They are neither
// inputs nor fixed: the server sends the current time.
func TestCacheBusterQueryParams(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("login").login(fxUser, fxPassword).endStep()
	b.step("list disks").click("Disks").get("/api/disks?_=1795255200123", fxDisks)
	b.get("/api/disks?_=1795255205456", fxDisks).endStep()
	b.step("system info").click("Info").get("/api/info?_dc=1795255210&lang=en", fxSysinfo).endStep()
	s := mustAnalyze(t, Options{}, b.build())
	disks := toolByName(t, s, "list_disks")
	if len(disks.Inputs) != 0 || disks.Request.Query["_"] != "{{now_ms}}" {
		t.Fatalf("list_disks = %+v %+v", disks.Inputs, disks.Request.Query)
	}
	info := toolByName(t, s, "system_info")
	if info.Request.Query["_dc"] != "{{now_s}}" || info.Request.Query["lang"] != "en" {
		t.Fatalf("system_info query = %+v", info.Request.Query)
	}
	if strings.Contains(notes(info.ReviewNotes), "_dc") {
		t.Errorf("unexpected note about _dc: %q", info.ReviewNotes)
	}

	// A time the user picked is not a cache buster: "time" is an ordinary
	// parameter name, and a timestamp that goes back between requests was
	// chosen, not stamped.
	t.Run("chosen times", func(t *testing.T) {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("history").click("History").get("/api/history?time=1795255200", fxOK)
		b.get("/api/history?time=1795000000", fxOK).endStep()
		b.step("events").click("Events").get("/api/events?ts=1795255200123", fxOK)
		b.get("/api/events?ts=1795100000000", fxOK).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		for _, c := range []struct{ tool, field string }{{"history", "time"}, {"events", "ts"}} {
			tl := toolByName(t, s, c.tool)
			if in := inputByName(t, tl, c.field); in.In != "query" {
				t.Errorf("%s: %s = %+v", c.tool, c.field, in)
			}
		}
	})
}

// OpenWrt LuCI and TP-Link routers put the session token in the URL path.
func TestSessionTokenInPath(t *testing.T) {
	record := func(stok string) *har.HAR {
		b := newHAR("http://router.lan/")
		b.loginStep("root", fxPassword, req{method: "POST", url: "/cgi-bin/luci/rpc/auth", reqMime: "application/json",
			reqBody: mustJSON(map[string]any{"username": "root", "password": fxPassword}), respMime: "application/json",
			respBody: `{"id":1,"result":{"stok":"` + stok + `"}}`})
		b.step("status").click("Status").get("/cgi-bin/luci/;stok="+stok+"/admin/status", map[string]any{"up": true}).endStep()
		b.step("reboot").click("Reboot").post("/cgi-bin/luci/;stok="+stok+"/admin/reboot", map[string]any{}, fxOK).endStep()
		return b.build()
	}
	const stok1, stok2 = "9f8e7d6c5b4a39281706", "0a1b2c3d4e5f60718293"
	s := mustAnalyze(t, Options{}, record(stok1))
	st := toolByName(t, s, "status")
	if st.Request.Path != "/cgi-bin/luci/;stok={stok}/admin/status" || st.Source.Key != "GET /cgi-bin/luci/;stok={stok}/admin/status" {
		t.Fatalf("status = %+v key %q", st.Request, st.Source.Key)
	}
	if len(st.Inputs) != 0 {
		t.Fatalf("the token must not be an input: %+v", st.Inputs)
	}
	var flow *spec.TokenFlow
	for i, tf := range s.Auth.Session.Tokens {
		if tf.To.Path != "" {
			flow = &s.Auth.Session.Tokens[i]
		}
	}
	if flow == nil || flow.To.Path != "stok" || flow.From.ResponseJSON != "result.stok" {
		t.Fatalf("tokens = %+v", s.Auth.Session.Tokens)
	}
	if y := specYAML(t, s); strings.Contains(y, stok1) {
		t.Fatalf("token in spec:\n%s", y)
	}
	// A second recording has a new token but the same tools.
	two := mustAnalyze(t, Options{}, record(stok1), record(stok2))
	if len(two.Tools) != 2 {
		t.Fatalf("tools = %v", toolNames(two))
	}
}

// A Wi-Fi key typed into a plain text field is never an example.
func TestTypedWifiKeyInTextField(t *testing.T) {
	b := newHAR(fxBase + "/")
	b.step("login").login(fxUser, fxPassword).endStep()
	b.step("set wifi", typed("Network", "ssid", "#ssid", "text", "HomeNet"), typed("Wi-Fi password", "key", "#key", "text", "Sunflower-2026")).
		click("Save").api("setwifi", map[string]any{"ssid": "HomeNet", "key": "Sunflower-2026"}, fxOK).endStep()
	s := mustAnalyze(t, Options{}, b.build())
	tl := toolByName(t, s, "set_wifi")
	if in := inputByName(t, tl, "key"); in.Example != nil {
		t.Fatalf("key = %+v", in)
	}
	if strings.Contains(specYAML(t, s), "Sunflower-2026") {
		t.Fatal("Wi-Fi key in spec")
	}
}

// Session tokens in XML or HTML responses become token flows, and a
// session-token field whose source is unknown is never an input.
func TestTextResponseTokens(t *testing.T) {
	t.Run("xml", func(t *testing.T) {
		const sid = "9a8b7c6d5e4f3a2b"
		b := newDevToolsHAR("http://fritz.box")
		b.add(req{method: "GET", url: "/login_sid.lua?version=2", respMime: "text/xml",
			respBody: `<?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>` + sid + `</SID><Challenge>2$600$aa</Challenge></SessionInfo>`})
		b.add(req{method: "POST", url: "/data.lua", reqMime: "application/x-www-form-urlencoded", reqBody: "xhr=1&sid=" + sid + "&page=overview",
			respMime: "application/json", respBody: `{"data":{"up":true}}`})
		b.add(req{method: "POST", url: "/data.lua", reqMime: "application/x-www-form-urlencoded", reqBody: "xhr=1&sid=" + sid + "&page=wlan",
			respMime: "application/json", respBody: `{"data":{"ssid":"HomeNet"}}`})
		s := mustAnalyze(t, Options{}, b.build())
		tl := toolByKey(t, s, "POST /data.lua")
		for _, in := range tl.Inputs {
			if in.Field == "sid" {
				t.Fatalf("sid is an input: %+v", tl.Inputs)
			}
		}
		if len(s.Auth.Session.Tokens) != 1 {
			t.Fatalf("tokens = %+v", s.Auth.Session.Tokens)
		}
		tf := s.Auth.Session.Tokens[0]
		if tf.To != (spec.TokenRef{Body: "sid"}) || tf.From.ResponseText == "" || tf.Request == nil || tf.Request.Path != "/login_sid.lua" {
			t.Fatalf("token flow = %+v request %+v", tf, tf.Request)
		}
		m := regexp.MustCompile(tf.From.ResponseText).FindStringSubmatch(`<SessionInfo><SID>00aa11bb22cc33dd</SID><Challenge>x</Challenge></SessionInfo>`)
		if len(m) != 2 || m[1] != "00aa11bb22cc33dd" {
			t.Fatalf("response_text %q does not find a new SID: %q", tf.From.ResponseText, m)
		}
		if strings.Contains(specYAML(t, s), sid) {
			t.Fatal("session id in spec")
		}
	})
	t.Run("html meta", func(t *testing.T) {
		const csrf = "Zx81kq2mN4pL7vQ0"
		b := newHAR(fxBase + "/")
		b.add(req{method: "GET", url: "/", resourceType: "document", respMime: "text/html",
			respBody: `<!doctype html><html><head><meta name="csrf-token" content="` + csrf + `"></head><body></body></html>`})
		b.loginStep(fxUser, fxPassword, req{method: "POST", url: "/api/login", reqMime: "application/json",
			reqBody: mustJSON(map[string]any{"username": fxUser, "password": fxPassword}), respMime: "application/json",
			respBody: `{"ok":true}`, setCookies: []har.Cookie{{Name: "NASSESSID", Value: fxSession}}})
		h := append(cookieHeader("NASSESSID="+fxSession), har.NameValue{Name: "X-CSRF-Token", Value: csrf})
		b.step("list disks").click("Disks").add(req{method: "POST", url: "/api.php", headers: h, reqMime: "application/json",
			reqBody: `{"act":"getdisklist"}`, respMime: "application/json", respBody: mustJSON(fxDisks)}).endStep()
		s := mustAnalyze(t, Options{}, b.build())
		var tf *spec.TokenFlow
		for i := range s.Auth.Session.Tokens {
			if s.Auth.Session.Tokens[i].To.Header == "X-CSRF-Token" {
				tf = &s.Auth.Session.Tokens[i]
			}
		}
		if tf == nil || tf.From.ResponseText == "" || tf.Request == nil || tf.Request.Path != "/" {
			t.Fatalf("tokens = %+v", s.Auth.Session.Tokens)
		}
		if strings.Contains(specYAML(t, s), csrf) {
			t.Fatal("token in spec")
		}
	})
	t.Run("unknown source", func(t *testing.T) {
		b := newDevToolsHAR(fxBase)
		b.add(req{method: "POST", url: "/api.cgi", reqMime: "application/x-www-form-urlencoded", reqBody: "sessionid=Ab12Cd34Ef56Gh78&cmd=status",
			respMime: "application/json", respBody: `{"up":true}`})
		s := mustAnalyze(t, Options{}, b.build())
		tl := toolByKey(t, s, "POST /api.cgi cmd=status")
		if len(tl.Inputs) != 0 || !tl.Review || !strings.Contains(notes(tl.ReviewNotes), "sessionid") {
			t.Fatalf("tool = %+v review %q", tl.Inputs, tl.ReviewNotes)
		}
	})
}

// Rerunning analyze after an input was edited (enhance edits input
// descriptions) still picks up a field that became an input.
func TestReanalyzeAfterInputEdit(t *testing.T) {
	record := func(name string, quota int) *har.HAR {
		b := newHAR(fxBase + "/")
		b.step("login").login(fxUser, fxPassword).endStep()
		b.step("add share", typed("Share name", "share-name", "#share-name", "text", name)).
			click("Add share").api("addshare", map[string]any{"name": name, "quota": quota}, fxOK).endStep()
		return b.build()
	}
	a, bb := record("media", 0), record("films", 100)
	existing := mustAnalyze(t, Options{}, a)
	tl := toolByName(t, existing, "add_share")
	if len(tl.Inputs) != 1 || tl.Request.Body["quota"] == nil {
		t.Fatalf("first analysis = %+v %v", tl.Inputs, tl.Request.Body)
	}
	tl.Inputs[0].Description = "Name of the new share."

	merged := spec.Merge(existing, mustAnalyze(t, Options{}, a, bb))
	if err := merged.Validate(); err != nil {
		t.Fatal(err)
	}
	got := toolByName(t, merged, "add_share")
	quota := inputByName(t, got, "quota")
	if quota.In != "body" || got.Request.Body["quota"] != nil {
		t.Fatalf("quota = %+v, body %v", quota, got.Request.Body)
	}
	if inputByName(t, got, "name").Description != "Name of the new share." {
		t.Fatalf("edited description lost: %+v", got.Inputs)
	}
}
