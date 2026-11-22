package record

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
)

// loginPages serves two login forms that send no submit event: one with a
// type=button login button (and a show-password toggle), as Element-UI and
// Vue forms do, and one that logs in on the Enter key.
func loginPages() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	})
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<!doctype html><title>login</title>`+body+`<script>
async function login(u, p) {
  const r = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({u: u, p: btoa(p)})});
  document.title = r.ok ? 'in' : 'no';
}
</script>`)
		}
	}
	mux.HandleFunc("/button", page(`<form id="f" onsubmit="return false">
<input id="u" name="user"> <input id="p" name="pass" type="password">
<button id="eye" type="button" aria-label="Show password">show</button>
<button id="go" type="button" onclick="login(u.value, p.value)">Log in</button>
</form>`))
	mux.HandleFunc("/enter", page(`<form id="f">
<input id="u" name="user"> <input id="p" name="pass" type="password"
  onkeydown="if (event.key === 'Enter') { event.preventDefault(); login(u.value, p.value); }">
</form>`))
	return httptest.NewServer(mux)
}

func TestRecordLoginWithoutSubmitEvent(t *testing.T) {
	needBrowser(t)
	ts := loginPages()
	defer ts.Close()
	waitIn := chromedp.Poll[chromedp.Void](`document.title === 'in'`,
		chromedp.WithPollingInterval(25*time.Millisecond), chromedp.WithPollingTimeout(15*time.Second))

	t.Run("button in a form", func(t *testing.T) {
		h, err := Run(testCtx(t), Options{URL: ts.URL + "/button", Headless: true, Script: func(ctx context.Context) error {
			return chromedp.Do(ctx,
				chromedp.WaitVisible(chromedp.CSS("#u")),
				chromedp.SendKeys(chromedp.CSS("#u"), "admin"),
				chromedp.SendKeys(chromedp.CSS("#p"), "s3cret-pw"),
				chromedp.Click(chromedp.CSS("#eye")),
				chromedp.Click(chromedp.CSS("#go")),
				waitIn,
			)
		}})
		if err != nil {
			t.Fatal(err)
		}
		l := h.Log.Har2mcp.Login
		if l == nil || l.Password != "s3cret-pw" || l.Username != "admin" || l.PasswordSelector != "#p" || l.SubmitSelector != "#go" {
			t.Fatalf("login capture = %+v", l)
		}
	})

	t.Run("enter key", func(t *testing.T) {
		h, err := Run(testCtx(t), Options{URL: ts.URL + "/enter", Headless: true, Script: func(ctx context.Context) error {
			return chromedp.Do(ctx,
				chromedp.WaitVisible(chromedp.CSS("#u")),
				chromedp.SendKeys(chromedp.CSS("#u"), "admin"),
				chromedp.SendKeys(chromedp.CSS("#p"), "s3cret-pw"),
				chromedp.SendKeys(chromedp.CSS("#p"), kb.Enter),
				waitIn,
			)
		}})
		if err != nil {
			t.Fatal(err)
		}
		l := h.Log.Har2mcp.Login
		if l == nil || l.Password != "s3cret-pw" || l.PasswordSelector != "#p" || l.SubmitSelector != "" {
			t.Fatalf("login capture = %+v", l)
		}
	})
}
