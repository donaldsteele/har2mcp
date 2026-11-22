package record

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/donaldsteele/har2mcp/internal/fakenas"
	"github.com/donaldsteele/har2mcp/internal/har"
)

// needBrowser skips browser tests in -short mode and where no browser is
// installed.
func needBrowser(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("browser test skipped in -short mode")
	}
	if _, err := FindBrowser(); err != nil {
		t.Skip("no browser: ", err)
	}
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// actEntry returns the POST /api.php entry whose JSON body has "act": act.
func actEntry(t *testing.T, h *har.HAR, act string) *har.Entry {
	t.Helper()
	for i := range h.Log.Entries {
		e := &h.Log.Entries[i]
		if !strings.HasSuffix(urlPath(e.Request.URL), "/api.php") || e.Request.PostData == nil {
			continue
		}
		var body map[string]any
		if json.Unmarshal([]byte(e.Request.PostData.Text), &body) == nil && body["act"] == act {
			return e
		}
	}
	t.Fatalf("no /api.php entry with act %q", act)
	return nil
}

func urlPath(u string) string {
	u, _, _ = strings.Cut(u, "?")
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.Index(u, "/"); i >= 0 {
		return u[i:]
	}
	return "/"
}

// pathEntries returns the entries for a URL path.
func pathEntries(h *har.HAR, path string) []*har.Entry {
	var out []*har.Entry
	for i := range h.Log.Entries {
		if urlPath(h.Log.Entries[i].Request.URL) == path {
			out = append(out, &h.Log.Entries[i])
		}
	}
	return out
}

func onlyEntry(t *testing.T, h *har.HAR, path string) *har.Entry {
	t.Helper()
	es := pathEntries(h, path)
	if len(es) != 1 {
		t.Fatalf("want 1 entry for %s, got %d", path, len(es))
	}
	return es[0]
}

func TestRecordLabeledSession(t *testing.T) {
	needBrowser(t)
	srv := fakenas.Start(fakenas.Config{})
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "session.har")

	h, err := Run(testCtx(t), Options{
		URL:      srv.URL,
		Out:      out,
		Headless: true,
		Script:   srv.Script(fakenas.ScriptOptions{}),
	})
	if err != nil {
		t.Fatal(err)
	}

	if h.Log.Version != "1.2" || h.Log.Creator.Name != "har2mcp" {
		t.Errorf("log version/creator = %q %+v", h.Log.Version, h.Log.Creator)
	}
	meta := h.Log.Har2mcp
	if meta == nil {
		t.Fatal("no _har2mcp block")
	}
	if meta.StartURL != srv.URL {
		t.Errorf("StartURL = %q, want %q", meta.StartURL, srv.URL)
	}
	var names []string
	for _, s := range meta.Steps {
		names = append(names, s.Name)
		if s.Start.IsZero() || !s.End.After(s.Start) {
			t.Errorf("step %q has times %v..%v", s.Name, s.Start, s.End)
		}
	}
	if want := []string{"login", "list disks", "add share", "upload file", "download file"}; !reflect.DeepEqual(names, want) {
		t.Errorf("steps = %q, want %q", names, want)
	}

	// The login form.
	if l := meta.Login; l == nil {
		t.Error("no login capture")
	} else {
		if l.Password != "hunter2-nas" || l.PasswordSelector != "#password" {
			t.Errorf("login password %q selector %q", l.Password, l.PasswordSelector)
		}
		if l.Username != "admin" || l.UsernameSelector != "#username" || l.SubmitSelector != "#login" {
			t.Errorf("login capture = %+v", l)
		}
		if !strings.HasPrefix(l.PageURL, srv.URL) {
			t.Errorf("login page URL = %q", l.PageURL)
		}
	}
	wantInputs := map[string]har.TypedInput{
		"#username": {Label: "Username", Name: "username", Selector: "#username", Type: "text", Value: "admin"},
		"#password": {Label: "Password", Name: "password", Selector: "#password", Type: "password", Value: "hunter2-nas"},
	}
	for _, in := range meta.Steps[0].Inputs {
		if w, ok := wantInputs[in.Selector]; ok {
			if in != w {
				t.Errorf("login input = %+v, want %+v", in, w)
			}
			delete(wantInputs, in.Selector)
		}
	}
	if len(wantInputs) > 0 {
		t.Errorf("login step lacks inputs %v; has %+v", wantInputs, meta.Steps[0].Inputs)
	}
	shareInput := false
	for _, in := range meta.Steps[2].Inputs {
		if in.Label == "Share name" && in.Value == "media" && in.Selector == "#share-name" {
			shareInput = true
		}
	}
	if !shareInput {
		t.Errorf("add share step lacks the typed share name: %+v", meta.Steps[2].Inputs)
	}

	// The requests.
	login := onlyEntry(t, h, "/api/login")
	if login.Step != "login" || login.Response.Status != 200 {
		t.Errorf("login entry step %q status %d", login.Step, login.Response.Status)
	}
	if login.Trigger == nil || login.Trigger.Selector != "#login" || login.Trigger.Text != "Log in" {
		t.Errorf("login trigger = %+v", login.Trigger)
	}
	if login.Request.PostData == nil || !strings.Contains(login.Request.PostData.Text, `"password":"hunter2-nas"`) {
		t.Errorf("login body = %+v", login.Request.PostData)
	}
	if !hasCookie(login.Response.Cookies, "NASSESSID") || !strings.Contains(login.Response.Header("Set-Cookie"), "NASSESSID=") {
		t.Errorf("login response lacks the session cookie: cookies %+v headers %+v", login.Response.Cookies, login.Response.Headers)
	}
	if !strings.Contains(login.Response.Content.Text, `"token"`) {
		t.Errorf("login response body = %q", login.Response.Content.Text)
	}

	disks := actEntry(t, h, "getdisklist")
	if disks.Step != "list disks" {
		t.Errorf("getdisklist _step = %q", disks.Step)
	}
	if disks.Trigger == nil || disks.Trigger.Text != "Disks" || disks.Trigger.Role != "button" || disks.Trigger.Selector != "#btn-disks" {
		t.Errorf("getdisklist _trigger = %+v", disks.Trigger)
	}
	if !strings.Contains(disks.Response.Content.Text, "sda") {
		t.Errorf("getdisklist response = %q", disks.Response.Content.Text)
	}
	if disks.ResourceType != "fetch" {
		t.Errorf("getdisklist _resourceType = %q", disks.ResourceType)
	}
	if !hasCookie(disks.Request.Cookies, "NASSESSID") || disks.Request.Header("Cookie") == "" {
		t.Errorf("getdisklist request lacks the session cookie: %+v", disks.Request.Headers)
	}
	if disks.Request.Header("X-Csrf-Token") == "" {
		t.Errorf("getdisklist request lacks X-Csrf-Token")
	}
	if disks.Time <= 0 || disks.StartedDateTime.IsZero() {
		t.Errorf("getdisklist time %v started %v", disks.Time, disks.StartedDateTime)
	}

	add := actEntry(t, h, "addshare")
	if add.Step != "add share" || add.Trigger == nil || add.Trigger.Text != "Add share" {
		t.Errorf("addshare step %q trigger %+v", add.Step, add.Trigger)
	}

	up := onlyEntry(t, h, "/api/upload")
	if up.Step != "upload file" || up.Request.PostData == nil || !strings.HasPrefix(up.Request.PostData.MimeType, "multipart/form-data") {
		t.Fatalf("upload entry step %q post %+v", up.Step, up.Request.PostData)
	}
	var sawPath, sawFile bool
	for _, p := range up.Request.PostData.Params {
		if p.Name == "path" && p.Value == "/public" {
			sawPath = true
		}
		if p.Name == "file" && p.FileName == "hello.txt" {
			sawFile = true
		}
	}
	if !sawPath || !sawFile {
		t.Errorf("upload params = %+v", up.Request.PostData.Params)
	}
	if string(srv.Files()["/public/hello.txt"]) != "hi" {
		t.Errorf("the upload did not reach the NAS: %v", srv.Files())
	}

	down := onlyEntry(t, h, "/api/download")
	if down.Step != "download file" || !strings.HasPrefix(down.Response.Header("Content-Disposition"), "attachment") {
		t.Errorf("download step %q headers %+v", down.Step, down.Response.Headers)
	}
	if b, err := down.Response.Content.Bytes(); err != nil || string(b) != "hi" {
		t.Errorf("download body = %q %v", b, err)
	}
	if len(down.Request.QueryString) != 1 || down.Request.QueryString[0].Value != "/public/hello.txt" {
		t.Errorf("download query = %+v", down.Request.QueryString)
	}

	// The page itself loads outside any step.
	for _, p := range []string{"/", "/static/app.js"} {
		for _, e := range pathEntries(h, p) {
			if e.Step != "" {
				t.Errorf("%s has _step %q", p, e.Step)
			}
		}
	}

	// The saved file.
	if runtime.GOOS != "windows" {
		st, err := os.Stat(out)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("recording mode = %v, want 0600", st.Mode().Perm())
		}
	}
	saved, err := har.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Log.Entries) != len(h.Log.Entries) || saved.Log.Har2mcp == nil || len(saved.Log.Har2mcp.Steps) != 5 {
		t.Errorf("saved HAR differs: %d entries", len(saved.Log.Entries))
	}
}

func hasCookie(cs []har.Cookie, name string) bool {
	for _, c := range cs {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}

// loginScript logs in to a fakenas SPA in a step named "login".
func loginScript(srv *fakenas.Server) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		if err := fakenas.StartStep(ctx, "login"); err != nil {
			return err
		}
		if err := chromedp.Do(ctx,
			chromedp.SendKeys(chromedp.CSS("#username"), fakenas.DefaultUser),
			chromedp.SendKeys(chromedp.CSS("#password"), fakenas.DefaultPassword),
		); err != nil {
			return err
		}
		if err := fakenas.ClickAndWait(ctx, "#login"); err != nil {
			return err
		}
		return fakenas.EndStep(ctx)
	}
}

func TestRecordInsecureTLS(t *testing.T) {
	needBrowser(t)
	srv := fakenas.Start(fakenas.Config{TLS: true})
	defer srv.Close()

	h, err := Run(testCtx(t), Options{URL: srv.URL, Insecure: true, Headless: true, Script: loginScript(srv)})
	if err != nil {
		t.Fatal(err)
	}
	login := onlyEntry(t, h, "/api/login")
	if !strings.HasPrefix(login.Request.URL, "https://") || login.Response.Status != 200 || login.Step != "login" {
		t.Errorf("login entry %s status %d step %q", login.Request.URL, login.Response.Status, login.Step)
	}
}

func TestRecordTLSWithoutInsecureFails(t *testing.T) {
	needBrowser(t)
	srv := fakenas.Start(fakenas.Config{TLS: true})
	defer srv.Close()

	_, err := Run(testCtx(t), Options{URL: srv.URL, Headless: true, Script: loginScript(srv)})
	if err == nil || !strings.Contains(err.Error(), "--insecure") {
		t.Fatalf("err = %v, want a hint about --insecure", err)
	}
}

func TestRecordBodyCap(t *testing.T) {
	needBrowser(t)
	srv := fakenas.Start(fakenas.Config{})
	defer srv.Close()

	h, err := Run(testCtx(t), Options{
		URL:      srv.URL,
		Headless: true,
		BodyCap:  16,
		Script: func(ctx context.Context) error {
			if err := loginScript(srv)(ctx); err != nil {
				return err
			}
			if err := fakenas.StartStep(ctx, "list disks"); err != nil {
				return err
			}
			if err := fakenas.ClickAndWait(ctx, "#btn-disks"); err != nil {
				return err
			}
			return fakenas.EndStep(ctx)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The request body is above the cap too, so find the call by its step.
	var disks *har.Entry
	for _, e := range pathEntries(h, "/api.php") {
		if e.Step == "list disks" {
			disks = e
		}
	}
	if disks == nil {
		t.Fatal("no /api.php entry in the step list disks")
	}
	c := disks.Response.Content
	if !c.Truncated || c.Text != "" || c.Size <= 16 {
		t.Errorf("disk list content = %+v, want truncated with no text", c)
	}
	// A request body above the cap loses its text too, and keeps its size.
	login := onlyEntry(t, h, "/api/login")
	if pd := login.Request.PostData; pd == nil || pd.Text != "" || login.Request.BodySize <= 16 {
		t.Errorf("login post data = %+v size %d", pd, login.Request.BodySize)
	}
	// A small body stays.
	if js := pathEntries(h, "/static/logo.png"); len(js) > 0 && js[0].Response.Content.Size > 16 && !js[0].Response.Content.Truncated {
		t.Errorf("logo.png (%d bytes) not truncated", js[0].Response.Content.Size)
	}
}

func TestOverlayBoxStartsAndEndsSteps(t *testing.T) {
	needBrowser(t)
	srv := fakenas.Start(fakenas.Config{})
	defer srv.Close()

	box := `document.querySelector('har2mcp-overlay').shadowRoot`
	h, err := Run(testCtx(t), Options{
		URL:      srv.URL,
		Headless: true,
		Script: func(ctx context.Context) error {
			// Start a step the way a person does: type a name in the box
			// and press its Start button.
			if err := chromedp.Do(ctx, chromedp.Evaluate[chromedp.Void](box+`.querySelector('input.name').value = 'sign in'; `+box+`.querySelector('button.go').click()`)); err != nil {
				return err
			}
			if err := chromedp.Do(ctx,
				chromedp.SendKeys(chromedp.CSS("#username"), "admin"),
				chromedp.SendKeys(chromedp.CSS("#password"), "hunter2-nas"),
			); err != nil {
				return err
			}
			if err := fakenas.ClickAndWait(ctx, "#login"); err != nil {
				return err
			}
			// The recorder pushes the request count to the box.
			if err := chromedp.Do(ctx, chromedp.Poll[chromedp.Void](
				`/^[1-9][0-9]* requests? this step$/.test(`+box+`.querySelector('.count').textContent)`,
				chromedp.WithPollingInterval(50*time.Millisecond), chromedp.WithPollingTimeout(10*time.Second))); err != nil {
				return fmt.Errorf("request count: %w", err)
			}
			label, err := chromedp.Run(ctx, chromedp.Evaluate[string](box+`.querySelector('button.go').textContent`))
			if err != nil || label != "Done" {
				return fmt.Errorf("button label %q (%v), want Done", label, err)
			}
			return chromedp.Do(ctx, chromedp.Evaluate[chromedp.Void](box+`.querySelector('button.go').click()`))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if steps := h.Log.Har2mcp.Steps; len(steps) != 1 || steps[0].Name != "sign in" {
		t.Fatalf("steps = %+v", steps)
	}
	login := onlyEntry(t, h, "/api/login")
	if login.Step != "sign in" {
		t.Errorf("login _step = %q", login.Step)
	}
	// Clicks in the box are not triggers.
	if login.Trigger == nil || login.Trigger.Text != "Log in" {
		t.Errorf("login _trigger = %+v", login.Trigger)
	}
}

func TestRecordScriptError(t *testing.T) {
	needBrowser(t)
	srv := fakenas.Start(fakenas.Config{})
	defer srv.Close()
	boom := errors.New("boom")
	out := filepath.Join(t.TempDir(), "x.har")
	_, err := Run(testCtx(t), Options{URL: srv.URL, Out: out, Headless: true, Script: func(context.Context) error { return boom }})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("a failed recording was saved: %v", err)
	}
}

func TestRecordCancelSavesSession(t *testing.T) {
	needBrowser(t)
	srv := fakenas.Start(fakenas.Config{})
	defer srv.Close()
	ctx, cancel := context.WithCancel(testCtx(t))
	out := filepath.Join(t.TempDir(), "cancel.har")
	h, err := Run(ctx, Options{URL: srv.URL, Out: out, Headless: true, Script: func(ctx context.Context) error {
		if err := loginScript(srv)(ctx); err != nil {
			return err
		}
		cancel() // like Ctrl+C in the middle of a session
		<-ctx.Done()
		return ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(pathEntries(h, "/api/login")) != 1 {
		t.Errorf("the login was not kept")
	}
	if _, err := har.Load(out); err != nil {
		t.Errorf("not saved: %v", err)
	}
}

// wsEcho is a minimal WebSocket server: it answers one text message with
// "pong: " + the message, then waits for the client to go away.
func wsEcho(w http.ResponseWriter, r *http.Request) {
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
	rw.Flush()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(rw, hdr); err != nil {
		return
	}
	n := int(hdr[1] & 0x7f) // the test message is short
	mask := make([]byte, 4)
	payload := make([]byte, n)
	if _, err := io.ReadFull(rw, mask); err != nil {
		return
	}
	if _, err := io.ReadFull(rw, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	reply := "pong: " + string(payload)
	conn.Write(append([]byte{0x81, byte(len(reply))}, reply...))
	io.Copy(io.Discard, rw)
}

func TestRecordWebSocket(t *testing.T) {
	needBrowser(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", wsEcho)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<!doctype html><title>ws</title><script>
const ws = new WebSocket('ws://' + location.host + '/ws');
ws.onopen = () => ws.send('ping');
ws.onmessage = (e) => { document.title = e.data; };
</script>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	h, err := Run(testCtx(t), Options{URL: ts.URL, Headless: true, Script: func(ctx context.Context) error {
		return chromedp.Do(ctx, chromedp.Poll[chromedp.Void](`document.title === 'pong: ping'`,
			chromedp.WithPollingInterval(25*time.Millisecond), chromedp.WithPollingTimeout(15*time.Second)))
	}})
	if err != nil {
		t.Fatal(err)
	}
	var ws *har.Entry
	for i := range h.Log.Entries {
		if h.Log.Entries[i].ResourceType == "websocket" {
			ws = &h.Log.Entries[i]
		}
	}
	if ws == nil {
		t.Fatal("no websocket entry")
	}
	if !strings.HasPrefix(ws.Request.URL, "ws://") || ws.Response.Status != 101 {
		t.Errorf("websocket entry %s status %d", ws.Request.URL, ws.Response.Status)
	}
	var got []string
	for _, m := range ws.WebSocketMessages {
		got = append(got, m.Type+":"+m.Data)
		if m.Opcode != 1 || m.Time < 1e9 {
			t.Errorf("message %+v", m)
		}
	}
	if want := []string{"send:ping", "receive:pong: ping"}; !reflect.DeepEqual(got, want) {
		t.Errorf("messages = %q, want %q", got, want)
	}
}

func TestRecordPopupTab(t *testing.T) {
	needBrowser(t)
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/popup-data", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true,"from":"popup"}`)
	})
	mux.HandleFunc("/popup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<!doctype html><title>popup</title><script>
setInterval(() => fetch('/api/popup-data'), 100);
</script>`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<!doctype html><title>main</title>
<button id="open" onclick="window.popup = window.open('/popup', 'p', 'width=400,height=300')">Open details</button>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	h, err := Run(testCtx(t), Options{URL: ts.URL, Headless: true, Script: func(ctx context.Context) error {
		if err := fakenas.StartStep(ctx, "open details"); err != nil {
			return err
		}
		if err := chromedp.Do(ctx, chromedp.Click(chromedp.CSS("#open"), chromedp.NodeVisible)); err != nil {
			return err
		}
		// The recorder injects its overlay into the popup once it records
		// the popup's traffic. Wait for that, then for a few more requests
		// from the popup.
		if err := chromedp.Do(ctx, chromedp.Poll[chromedp.Void](`!!(window.popup && window.popup.__har2mcp)`,
			chromedp.WithPollingInterval(25*time.Millisecond), chromedp.WithPollingTimeout(30*time.Second))); err != nil {
			return fmt.Errorf("the recorder did not attach to the popup: %w", err)
		}
		from := hits.Load()
		deadline := time.Now().Add(15 * time.Second)
		for hits.Load() < from+5 {
			if time.Now().After(deadline) {
				return fmt.Errorf("the popup made only %d requests", hits.Load())
			}
			time.Sleep(50 * time.Millisecond)
		}
		return fakenas.EndStep(ctx)
	}})
	if err != nil {
		t.Fatal(err)
	}
	es := pathEntries(h, "/api/popup-data")
	if len(es) == 0 {
		t.Fatal("no requests from the popup tab were recorded")
	}
	tagged := 0
	for _, e := range es {
		if e.Step == "open details" && strings.Contains(e.Response.Content.Text, "popup") {
			tagged++
		}
	}
	if tagged == 0 {
		t.Errorf("popup requests are not in the step: %+v", es[0])
	}
}

func TestRunRejectsBadURL(t *testing.T) {
	for _, u := range []string{"", "ftp://nas.local/", "nas.local", "http://"} {
		if _, err := Run(context.Background(), Options{URL: u}); err == nil || !regexp.MustCompile(`not an http`).MatchString(err.Error()) {
			t.Errorf("Run(%q) err = %v", u, err)
		}
	}
	if _, err := Run(context.Background(), Options{URL: "http://127.0.0.1:1", BrowserPath: filepath.Join(t.TempDir(), "nope")}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing browser: err = %v", err)
	}
}

// TestRecordInteractiveEnds covers a session a person drives (no Script):
// it ends on Ctrl+C, when the person closes the tab, or when the browser
// exits, and each time the recording up to then is saved.
func TestRecordInteractiveEnds(t *testing.T) {
	needBrowser(t)
	enders := map[string]func(ctx context.Context, cancel context.CancelFunc) error{
		"ctrl+c": func(ctx context.Context, cancel context.CancelFunc) error {
			cancel()
			return nil
		},
		"tab closed": func(ctx context.Context, cancel context.CancelFunc) error {
			_, err := chromedp.CallBrowser(ctx, target.CloseTarget, target.CloseTargetParams{TargetID: chromedp.FromContext(ctx).Target.TargetID})
			return err
		},
		"browser exits": func(ctx context.Context, cancel context.CancelFunc) error {
			return chromedp.FromContext(ctx).Browser.Process().Kill()
		},
	}
	for name, end := range enders {
		t.Run(name, func(t *testing.T) {
			srv := fakenas.Start(fakenas.Config{})
			defer srv.Close()
			ctx, cancel := context.WithCancel(testCtx(t))
			defer cancel()
			hookErr := make(chan error, 1)
			testHookWaiting = func(tabCtx context.Context) {
				if err := loginScript(srv)(tabCtx); err != nil {
					hookErr <- err
					cancel()
					return
				}
				// Let the recorder fetch the login response body first.
				time.Sleep(300 * time.Millisecond)
				hookErr <- end(tabCtx, cancel)
			}
			t.Cleanup(func() { testHookWaiting = nil })

			out := filepath.Join(t.TempDir(), "s.har")
			done := make(chan struct{})
			var h *har.HAR
			var err error
			go func() {
				h, err = Run(ctx, Options{URL: srv.URL, Out: out, Headless: true})
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(60 * time.Second):
				t.Fatal("Run did not return after the session ended")
			}
			if herr := <-hookErr; herr != nil {
				t.Fatalf("driving the session: %v", herr)
			}
			if err != nil {
				t.Fatal(err)
			}
			login := onlyEntry(t, h, "/api/login")
			if login.Step != "login" || !strings.Contains(login.Response.Content.Text, "token") {
				t.Errorf("login entry step %q body %q", login.Step, login.Response.Content.Text)
			}
			if _, err := har.Load(out); err != nil {
				t.Errorf("not saved: %v", err)
			}
		})
	}
}

// TestRecordScrambledLogin records the Scramble variant: the page hashes the
// password with a nonce, so the login request does not carry the typed
// password, while the login capture does.
func TestRecordScrambledLogin(t *testing.T) {
	needBrowser(t)
	srv := fakenas.Start(fakenas.Config{Scramble: true})
	defer srv.Close()

	h, err := Run(testCtx(t), Options{URL: srv.URL, Headless: true, Script: srv.Script(fakenas.ScriptOptions{})})
	if err != nil {
		t.Fatal(err)
	}
	nonce := onlyEntry(t, h, "/api/nonce")
	login := onlyEntry(t, h, "/api/login")
	if nonce.Step != "login" || login.Step != "login" || login.Response.Status != 200 {
		t.Errorf("nonce step %q, login step %q status %d", nonce.Step, login.Step, login.Response.Status)
	}
	var body struct{ Username, Password string }
	if err := json.Unmarshal([]byte(login.Request.PostData.Text), &body); err != nil {
		t.Fatal(err)
	}
	if body.Username != "admin" || body.Password == "hunter2-nas" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(body.Password) {
		t.Errorf("login body = %+v, want a sha256 hex password", body)
	}
	if l := h.Log.Har2mcp.Login; l == nil || l.Password != "hunter2-nas" {
		t.Errorf("login capture = %+v", l)
	}
	if len(h.Log.Har2mcp.Steps) != 5 {
		t.Errorf("steps = %+v", h.Log.Har2mcp.Steps)
	}
	actEntry(t, h, "getdisklist")
}
