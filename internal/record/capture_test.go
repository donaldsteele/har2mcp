package record

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/donaldsteele/har2mcp/internal/har"
)

// These tests feed DevTools events to a recorder directly, so the capture
// logic is covered on machines without a browser.

func newTestRecorder(bodyCap int64) (*recorder, *tab) {
	r := newRecorder(bodyCap)
	return r, r.newTab()
}

// takeJobs returns and clears the queued jobs of a tab.
func takeJobs(tb *tab) []job {
	tb.qmu.Lock()
	defer tb.qmu.Unlock()
	q := tb.queue
	tb.queue = nil
	return q
}

// finishBody completes a queued body job the way the worker does.
func finishBody(r *recorder, j job, body string) {
	r.mu.Lock()
	r.setBody(j.rr, []byte(body))
	r.jobs--
	r.mu.Unlock()
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func epoch(t time.Time) cdp.TimeSinceEpoch {
	return cdp.TimeSinceEpoch(float64(t.UnixNano()) / 1e9)
}

func TestCaptureHTTPEntry(t *testing.T) {
	r, tb := newTestRecorder(DefaultBodyCap)
	start := time.Date(2026, 11, 21, 10, 0, 0, 250_000_000, time.UTC)
	r.onEvent(tb, &network.EventRequestWillBeSent{
		RequestID: "1",
		Request: &network.Request{
			URL:         "http://nas.local/api.php?x=1&y=a%20b",
			Method:      "POST",
			Headers:     network.Headers{"Content-Type": "application/json"},
			HasPostData: true,
			PostDataEntries: []*network.PostDataEntry{
				{Bytes: []byte(`{"act":`)}, {Bytes: []byte(`"getdisklist"}`)},
			},
		},
		Timestamp: 100,
		WallTime:  epoch(start),
		Type:      network.ResourceTypeFetch,
	})
	r.onEvent(tb, &network.EventRequestWillBeSentExtraInfo{RequestID: "1", Headers: network.Headers{
		"Content-Type": "application/json",
		"Cookie":       "NASSESSID=abc; lang=en",
		"X-Csrf-Token": "tok",
	}})
	headersText := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
	r.onEvent(tb, &network.EventResponseReceivedExtraInfo{RequestID: "1", StatusCode: 200, HeadersText: headersText, Headers: network.Headers{
		"Content-Type": "application/json",
		"Set-Cookie":   "a=1; Path=/; HttpOnly\nb=2; Secure; Max-Age=60",
	}})
	r.onEvent(tb, &network.EventResponseReceived{RequestID: "1", Timestamp: 100.010, Type: network.ResourceTypeFetch, Response: &network.Response{
		Status: 200, StatusText: "OK", MimeType: "application/json", Protocol: "http/1.1",
		Headers: network.Headers{"Content-Type": "application/json"},
		Timing:  &network.ResourceTiming{RequestTime: 100, SendStart: 1, SendEnd: 2, ReceiveHeadersEnd: 10},
	}})
	r.onEvent(tb, &network.EventDataReceived{RequestID: "1", DataLength: 11})
	r.onEvent(tb, &network.EventLoadingFinished{RequestID: "1", Timestamp: 100.015, EncodedDataLength: 120, EncodedBodyLength: 11})

	jobs := takeJobs(tb)
	if len(jobs) != 1 || jobs[0].kind != jobBody {
		t.Fatalf("jobs = %+v", jobs)
	}
	if r.inflight != 0 || r.jobs != 1 {
		t.Errorf("inflight %d jobs %d", r.inflight, r.jobs)
	}
	finishBody(r, jobs[0], `{"ok":true}`)

	h := r.build("http://nas.local/", time.Now())
	if len(h.Log.Entries) != 1 {
		t.Fatalf("entries = %d", len(h.Log.Entries))
	}
	e := h.Log.Entries[0]
	if !e.StartedDateTime.Equal(start) || e.ResourceType != "fetch" {
		t.Errorf("started %v type %q", e.StartedDateTime, e.ResourceType)
	}
	q := e.Request
	if q.Method != "POST" || q.URL != "http://nas.local/api.php?x=1&y=a%20b" || q.HTTPVersion != "HTTP/1.1" {
		t.Errorf("request line %s %s %s", q.Method, q.URL, q.HTTPVersion)
	}
	if want := []har.NameValue{{Name: "x", Value: "1"}, {Name: "y", Value: "a b"}}; !reflect.DeepEqual(q.QueryString, want) {
		t.Errorf("query = %+v", q.QueryString)
	}
	if want := []har.Cookie{{Name: "NASSESSID", Value: "abc"}, {Name: "lang", Value: "en"}}; !reflect.DeepEqual(q.Cookies, want) {
		t.Errorf("request cookies = %+v", q.Cookies)
	}
	if q.Header("X-Csrf-Token") != "tok" || q.Header("Cookie") == "" {
		t.Errorf("request headers did not come from the extra info: %+v", q.Headers)
	}
	if q.PostData == nil || q.PostData.Text != `{"act":"getdisklist"}` || q.PostData.MimeType != "application/json" || q.BodySize != 21 {
		t.Errorf("post data = %+v size %d", q.PostData, q.BodySize)
	}

	p := e.Response
	if p.Status != 200 || p.StatusText != "OK" || p.HTTPVersion != "HTTP/1.1" {
		t.Errorf("status %d %q %s", p.Status, p.StatusText, p.HTTPVersion)
	}
	if len(p.Cookies) != 2 || p.Cookies[0].Name != "a" || !p.Cookies[0].HTTPOnly || p.Cookies[0].Path != "/" ||
		p.Cookies[1].Name != "b" || !p.Cookies[1].Secure || p.Cookies[1].Expires == nil {
		t.Errorf("response cookies = %+v", p.Cookies)
	}
	setCookies := 0
	for _, hv := range p.Headers {
		if hv.Name == "Set-Cookie" {
			setCookies++
		}
	}
	if setCookies != 2 {
		t.Errorf("Set-Cookie headers = %d, want 2: %+v", setCookies, p.Headers)
	}
	if p.Content.Text != `{"ok":true}` || p.Content.Size != 11 || p.Content.MimeType != "application/json" || p.Content.Encoding != "" {
		t.Errorf("content = %+v", p.Content)
	}
	if p.BodySize != 11 || p.HeadersSize != int64(len(headersText)) {
		t.Errorf("body size %d headers size %d", p.BodySize, p.HeadersSize)
	}
	if !near(e.Timings.Send, 1) || !near(e.Timings.Receive, 5) || !near(e.Timings.Wait, 9) || !near(e.Time, 15) {
		t.Errorf("timings %+v time %v", e.Timings, e.Time)
	}
}

func TestCaptureRedirectHops(t *testing.T) {
	r, tb := newTestRecorder(DefaultBodyCap)
	now := time.Now()
	r.onEvent(tb, &network.EventRequestWillBeSent{RequestID: "7", Timestamp: 10, WallTime: epoch(now),
		Request: &network.Request{URL: "http://nas.local/a", Method: "GET"}, Type: network.ResourceTypeDocument})
	r.onEvent(tb, &network.EventRequestWillBeSentExtraInfo{RequestID: "7", Headers: network.Headers{"Cookie": "c=1"}})
	r.onEvent(tb, &network.EventResponseReceivedExtraInfo{RequestID: "7", StatusCode: 302, Headers: network.Headers{"Location": "/b"}})
	r.onEvent(tb, &network.EventRequestWillBeSent{RequestID: "7", Timestamp: 10.1, WallTime: epoch(now.Add(100 * time.Millisecond)),
		Request:          &network.Request{URL: "http://nas.local/b", Method: "GET"},
		RedirectResponse: &network.Response{Status: 302, Headers: network.Headers{"Location": "/b"}},
		Type:             network.ResourceTypeDocument})
	r.onEvent(tb, &network.EventRequestWillBeSentExtraInfo{RequestID: "7", Headers: network.Headers{"Cookie": "c=2"}})
	r.onEvent(tb, &network.EventResponseReceivedExtraInfo{RequestID: "7", StatusCode: 200, Headers: network.Headers{"Content-Type": "text/html"}})
	r.onEvent(tb, &network.EventResponseReceived{RequestID: "7", Timestamp: 10.2, Response: &network.Response{Status: 200, Headers: network.Headers{"Content-Type": "text/html"}}})
	r.onEvent(tb, &network.EventLoadingFinished{RequestID: "7", Timestamp: 10.3})
	for _, j := range takeJobs(tb) {
		finishBody(r, j, "<p>b</p>")
	}

	es := r.build("http://nas.local/", time.Now()).Log.Entries
	if len(es) != 2 {
		t.Fatalf("entries = %d", len(es))
	}
	if es[0].Request.URL != "http://nas.local/a" || es[0].Response.Status != 302 || es[0].Response.RedirectURL != "http://nas.local/b" ||
		es[0].Request.Header("Cookie") != "c=1" || es[0].Response.Header("Location") != "/b" || es[0].Response.Content.Text != "" {
		t.Errorf("hop 1 = %+v", es[0])
	}
	if es[1].Request.URL != "http://nas.local/b" || es[1].Response.Status != 200 || es[1].Request.Header("Cookie") != "c=2" ||
		es[1].Response.Content.Text != "<p>b</p>" || es[1].Response.StatusText != "OK" {
		t.Errorf("hop 2 = %+v", es[1])
	}
	if r.inflight != 0 {
		t.Errorf("inflight = %d", r.inflight)
	}
}

func TestCaptureSkipsNonHTTPAndPreflight(t *testing.T) {
	r, tb := newTestRecorder(DefaultBodyCap)
	for i, u := range []string{"data:text/plain,hi", "blob:http://nas.local/1", "chrome-extension://x/y", "about:blank"} {
		r.onEvent(tb, &network.EventRequestWillBeSent{RequestID: network.RequestID(rune('a' + i)), Request: &network.Request{URL: u, Method: "GET"}})
	}
	r.onEvent(tb, &network.EventRequestWillBeSent{RequestID: "p", Type: network.ResourceTypePreflight,
		Request: &network.Request{URL: "http://other.local/api", Method: "OPTIONS"}})
	if n := len(r.build("http://nas.local/", time.Now()).Log.Entries); n != 0 || r.inflight != 0 {
		t.Errorf("entries %d inflight %d, want none", n, r.inflight)
	}
}

func TestCaptureFailedRequest(t *testing.T) {
	r, tb := newTestRecorder(DefaultBodyCap)
	r.onEvent(tb, &network.EventRequestWillBeSent{RequestID: "f", Timestamp: 1, WallTime: epoch(time.Now()),
		Request: &network.Request{URL: "http://nas.local/api", Method: "GET"}})
	r.onEvent(tb, &network.EventLoadingFailed{RequestID: "f", Timestamp: 1.5, ErrorText: "net::ERR_CONNECTION_REFUSED"})
	r.onEvent(tb, &network.EventRequestWillBeSent{RequestID: "g", Timestamp: 2, WallTime: epoch(time.Now()),
		Request: &network.Request{URL: "http://nas.local/dl", Method: "GET"}})
	r.onEvent(tb, &network.EventResponseReceived{RequestID: "g", Timestamp: 2.1, Response: &network.Response{Status: 200,
		Headers: network.Headers{"Content-Disposition": `attachment; filename="x.bin"`}}})
	r.onEvent(tb, &network.EventLoadingFailed{RequestID: "g", Timestamp: 2.2, Canceled: true})

	es := r.build("http://nas.local/", time.Now()).Log.Entries
	if es[0].Response.Status != 0 || es[0].Response.StatusText != "net::ERR_CONNECTION_REFUSED" || !near(es[0].Time, 500) {
		t.Errorf("failed entry = %+v time %v", es[0].Response, es[0].Time)
	}
	// A navigation that became a download is cancelled after its headers
	// arrive; the headers stay.
	if es[1].Response.Status != 200 || !strings.HasPrefix(es[1].Response.Header("Content-Disposition"), "attachment") {
		t.Errorf("cancelled download = %+v", es[1].Response)
	}
	if len(takeJobs(tb)) != 0 || r.inflight != 0 {
		t.Errorf("failed requests queued work or stayed in flight")
	}
}

func TestCaptureBodyCap(t *testing.T) {
	r, tb := newTestRecorder(16)
	send := func(id, url string, dataLen int64, headers network.Headers) {
		r.onEvent(tb, &network.EventRequestWillBeSent{RequestID: network.RequestID(id), Timestamp: 1, WallTime: epoch(time.Now()),
			Request: &network.Request{URL: url, Method: "GET"}})
		r.onEvent(tb, &network.EventResponseReceived{RequestID: network.RequestID(id), Timestamp: 1.1,
			Response: &network.Response{Status: 200, Headers: headers, MimeType: "application/json"}})
		r.onEvent(tb, &network.EventDataReceived{RequestID: network.RequestID(id), DataLength: dataLen})
		r.onEvent(tb, &network.EventLoadingFinished{RequestID: network.RequestID(id), Timestamp: 1.2})
	}
	send("big-seen", "http://nas.local/a", 100, nil) // over the cap by its data events: not fetched
	send("big-body", "http://nas.local/b", 0, nil)   // over the cap once fetched
	send("small", "http://nas.local/c", 0, nil)
	send("drained", "http://nas.local/d", 0, network.Headers{"Content-Length": "42"})
	send("empty", "http://nas.local/e", 0, network.Headers{"Content-Length": "0"})

	jobs := takeJobs(tb)
	if len(jobs) != 4 {
		t.Fatalf("jobs = %d, want 4 (no fetch for a body seen above the cap)", len(jobs))
	}
	bodies := map[string]string{
		"http://nas.local/b": strings.Repeat("x", 17),
		"http://nas.local/c": `{"ok":1}`,
		"http://nas.local/d": "",
		"http://nas.local/e": "",
	}
	for _, j := range jobs {
		finishBody(r, j, bodies[j.rr.url])
	}
	got := map[string]har.Content{}
	for _, e := range r.build("http://nas.local/", time.Now()).Log.Entries {
		got[e.Request.URL] = e.Response.Content
	}
	if c := got["http://nas.local/a"]; !c.Truncated || c.Text != "" || c.Size != 100 {
		t.Errorf("a = %+v", c)
	}
	if c := got["http://nas.local/b"]; !c.Truncated || c.Text != "" || c.Size != 17 {
		t.Errorf("b = %+v", c)
	}
	if c := got["http://nas.local/c"]; c.Truncated || c.Text != `{"ok":1}` || c.Size != 8 {
		t.Errorf("c = %+v", c)
	}
	if c := got["http://nas.local/d"]; c.Truncated || c.Text != "" || c.Size != 42 {
		t.Errorf("d (body not available) = %+v", c)
	}
	if c := got["http://nas.local/e"]; c.Truncated || c.Text != "" || c.Size != 0 {
		t.Errorf("e (empty) = %+v", c)
	}
}

func TestCaptureBinaryBodyIsBase64(t *testing.T) {
	r, tb := newTestRecorder(DefaultBodyCap)
	r.onEvent(tb, &network.EventRequestWillBeSent{RequestID: "1", Timestamp: 1, WallTime: epoch(time.Now()),
		Request: &network.Request{URL: "http://nas.local/b.bin", Method: "GET"}})
	r.onEvent(tb, &network.EventResponseReceived{RequestID: "1", Timestamp: 1.1, Response: &network.Response{Status: 200,
		Headers: network.Headers{"Content-Type": "application/octet-stream"}}})
	r.onEvent(tb, &network.EventLoadingFinished{RequestID: "1", Timestamp: 1.2})
	finishBody(r, takeJobs(tb)[0], "\x00\x01\xff")
	c := r.build("", time.Now()).Log.Entries[0].Response.Content
	b, err := c.Bytes()
	if c.Encoding != "base64" || err != nil || string(b) != "\x00\x01\xff" || c.Size != 3 {
		t.Errorf("content = %+v bytes %q %v", c, b, err)
	}
}

func TestCapturePostDataOmitted(t *testing.T) {
	r, tb := newTestRecorder(64)
	const ct = "multipart/form-data; boundary=XX"
	r.onEvent(tb, &network.EventRequestWillBeSent{RequestID: "m", Timestamp: 1, WallTime: epoch(time.Now()),
		Request: &network.Request{URL: "http://nas.local/api/upload", Method: "POST", HasPostData: true,
			Headers: network.Headers{"Content-Type": ct}}})
	r.onEvent(tb, &network.EventRequestWillBeSentExtraInfo{RequestID: "m", Headers: network.Headers{"Content-Type": ct, "Content-Length": "5000"}})
	r.onEvent(tb, &network.EventRequestWillBeSent{RequestID: "raw", Timestamp: 1, WallTime: epoch(time.Now()),
		Request: &network.Request{URL: "http://nas.local/api/chunk", Method: "PUT", HasPostData: true,
			Headers: network.Headers{"Content-Type": "application/octet-stream", "Content-Length": "4194304"}}})

	jobs := takeJobs(tb)
	if len(jobs) != 1 || jobs[0].kind != jobPostData || jobs[0].rr.url != "http://nas.local/api/upload" {
		t.Fatalf("jobs = %+v, want one post-data fetch for the multipart body", jobs)
	}
	body := "--XX\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n/public\r\n" +
		"--XX\r\nContent-Disposition: form-data; name=\"file\"; filename=\"big.iso\"\r\nContent-Type: application/x-iso9660-image\r\n\r\n\r\n--XX--\r\n"
	r.mu.Lock()
	jobs[0].rr.postData = []byte(body)
	jobs[0].rr.postOmitted = int64(len(body)) > r.bodyCap
	r.jobs--
	r.mu.Unlock()

	es := r.build("", time.Now()).Log.Entries
	up, raw := es[0].Request, es[1].Request
	if up.URL != "http://nas.local/api/upload" {
		up, raw = raw, up
	}
	want := []har.Param{{Name: "path", Value: "/public"}, {Name: "file", FileName: "big.iso", ContentType: "application/x-iso9660-image"}}
	if up.PostData == nil || !reflect.DeepEqual(up.PostData.Params, want) || up.BodySize != 5000 || up.PostData.Text != "" {
		t.Errorf("upload post data = %+v size %d", up.PostData, up.BodySize)
	}
	if raw.PostData == nil || raw.PostData.Text != "" || raw.BodySize != 4194304 || raw.PostData.MimeType != "application/octet-stream" {
		t.Errorf("raw post data = %+v size %d", raw.PostData, raw.BodySize)
	}
}

func TestCaptureWebSocket(t *testing.T) {
	r, tb := newTestRecorder(DefaultBodyCap)
	start := time.Now().UTC().Truncate(time.Microsecond)
	r.onEvent(tb, &network.EventWebSocketCreated{RequestID: "w", URL: "ws://nas.local/events?ch=1"})
	r.onEvent(tb, &network.EventWebSocketCreated{RequestID: "x", URL: "http://not-a-socket/"})
	r.onEvent(tb, &network.EventWebSocketWillSendHandshakeRequest{RequestID: "w", Timestamp: 50, WallTime: epoch(start),
		Request: &network.WebSocketRequest{Headers: network.Headers{"Cookie": "NASSESSID=abc"}}})
	r.onEvent(tb, &network.EventWebSocketHandshakeResponseReceived{RequestID: "w", Timestamp: 50.01,
		Response: &network.WebSocketResponse{Status: 101, StatusText: "Switching Protocols", Headers: network.Headers{"Upgrade": "websocket"}}})
	r.onEvent(tb, &network.EventWebSocketFrameSent{RequestID: "w", Timestamp: 50.5, Response: &network.WebSocketFrame{Opcode: 1, PayloadData: []byte("hi")}})
	r.onEvent(tb, &network.EventWebSocketFrameReceived{RequestID: "w", Timestamp: 51, Response: &network.WebSocketFrame{Opcode: 2, PayloadData: []byte{0, 1}}})
	r.onEvent(tb, &network.EventWebSocketClosed{RequestID: "w", Timestamp: 52})

	es := r.build("", time.Now()).Log.Entries
	if len(es) != 1 {
		t.Fatalf("entries = %d", len(es))
	}
	e := es[0]
	if e.ResourceType != "websocket" || e.Request.URL != "ws://nas.local/events?ch=1" || e.Request.Method != "GET" ||
		e.Response.Status != 101 || !hasCookie(e.Request.Cookies, "NASSESSID") || len(e.Request.QueryString) != 1 {
		t.Errorf("entry = %+v", e)
	}
	if !e.StartedDateTime.Equal(start) || !near(e.Time, 2000) {
		t.Errorf("started %v time %v", e.StartedDateTime, e.Time)
	}
	m := e.WebSocketMessages
	if len(m) != 2 || m[0].Type != "send" || m[0].Data != "hi" || m[0].Opcode != 1 ||
		m[1].Type != "receive" || m[1].Data != "AAE=" || m[1].Opcode != 2 {
		t.Fatalf("messages = %+v", m)
	}
	if want := float64(start.UnixNano())/1e9 + 0.5; math.Abs(m[0].Time-want) > 1e-3 {
		t.Errorf("message time %v, want %v", m[0].Time, want)
	}
}

// emit sends an overlay event as the page would.
func emit(r *recorder, tb *tab, ev map[string]any) {
	b, _ := json.Marshal(ev)
	r.onEvent(tb, &runtime.EventBindingCalled{Name: BindingName, Payload: string(b)})
}

func ms(t time.Time) float64 { return float64(t.UnixMilli()) }

func TestStepAndTriggerTagging(t *testing.T) {
	r, tb := newTestRecorder(DefaultBodyCap)
	base := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	at := func(d time.Duration) time.Time { return base.Add(d) }
	req := func(id string, d time.Duration) {
		r.onEvent(tb, &network.EventRequestWillBeSent{RequestID: network.RequestID(id), Timestamp: cdp.MonotonicTime(d.Seconds()),
			WallTime: epoch(at(d)), Request: &network.Request{URL: "http://nas.local/" + id, Method: "GET"}})
	}

	req("before", 500*time.Millisecond)
	emit(r, tb, map[string]any{"type": "step_start", "name": "list disks", "t": ms(at(time.Second))})
	emit(r, tb, map[string]any{"type": "click", "text": "Disks", "role": "button", "selector": "#btn-disks", "t": ms(at(1500 * time.Millisecond))})
	req("clicked", 1600*time.Millisecond)
	req("late", 4*time.Second) // more than 2 s after the click
	emit(r, tb, map[string]any{"type": "click", "text": "Later", "t": ms(at(5050 * time.Millisecond))})
	req("before-click", 5*time.Second) // 50 ms before the next click
	emit(r, tb, map[string]any{"type": "step_end", "t": ms(at(6 * time.Second))})
	req("after", 6100*time.Millisecond)
	emit(r, tb, map[string]any{"type": "step_start", "name": "", "t": ms(at(7 * time.Second))})
	req("open", 8*time.Second)

	if r.stepCount != 1 {
		t.Errorf("request count of the running step = %d, want 1", r.stepCount)
	}
	h := r.build("", at(9*time.Second))
	got := map[string][2]string{}
	for _, e := range h.Log.Entries {
		trig := ""
		if e.Trigger != nil {
			trig = e.Trigger.Text
		}
		got[strings.TrimPrefix(e.Request.URL, "http://nas.local/")] = [2]string{e.Step, trig}
	}
	want := map[string][2]string{
		"before":       {"", ""},
		"clicked":      {"list disks", "Disks"},
		"late":         {"list disks", ""},
		"before-click": {"list disks", ""},
		"after":        {"", "Later"}, // 1.05 s after that click
		"open":         {"", ""},      // the second step is named ""
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tags = %v\nwant   %v", got, want)
	}
	steps := h.Log.Har2mcp.Steps
	if len(steps) != 2 || !steps[0].End.Equal(at(6*time.Second)) || !steps[1].End.Equal(at(9*time.Second)) {
		t.Errorf("steps = %+v", steps)
	}
	if e := h.Log.Entries[1]; e.Trigger == nil || e.Trigger.Selector != "#btn-disks" || e.Trigger.Role != "button" {
		t.Errorf("trigger = %+v", e.Trigger)
	}
}

func TestOverlayInputsAndLogin(t *testing.T) {
	r, tb := newTestRecorder(DefaultBodyCap)
	now := ms(time.Now())
	emit(r, tb, map[string]any{"type": "input", "selector": "#ignored", "value": "outside a step", "t": now})
	emit(r, tb, map[string]any{"type": "step_start", "name": "add share", "t": now})
	emit(r, tb, map[string]any{"type": "input", "label": "Share name", "name": "name", "selector": "#share-name", "inputType": "text", "value": "med", "t": now})
	emit(r, tb, map[string]any{"type": "input", "label": "Comment", "selector": "#c", "inputType": "textarea", "value": "x", "t": now})
	emit(r, tb, map[string]any{"type": "input", "label": "Share name", "name": "name", "selector": "#share-name", "inputType": "text", "value": "media", "t": now})
	emit(r, tb, map[string]any{"type": "login_submit", "password": "", "t": now})
	emit(r, tb, map[string]any{"type": "login_submit", "usernameSelector": "#u", "passwordSelector": "#p", "submitSelector": "#go",
		"username": "admin", "password": "typo", "pageUrl": "http://nas.local/login", "t": now})
	// A retry on the same form replaces the capture...
	emit(r, tb, map[string]any{"type": "login_submit", "usernameSelector": "#u", "passwordSelector": "#p", "submitSelector": "#go",
		"username": "admin", "password": "pw1", "pageUrl": "http://nas.local/login?retry=1#x", "t": now})
	// ...another form with a password field, such as "add user", does not.
	emit(r, tb, map[string]any{"type": "login_submit", "usernameSelector": "#new-user", "passwordSelector": "#new-pw",
		"username": "bob", "password": "bobpw", "pageUrl": "http://nas.local/login", "t": now})
	emit(r, tb, map[string]any{"type": "login_submit", "usernameSelector": "#u", "passwordSelector": "#p",
		"username": "bob", "password": "bobpw", "pageUrl": "http://nas.local/users", "t": now})
	emit(r, tb, map[string]any{"type": "step_start", "name": "second", "t": now + 10})
	emit(r, tb, map[string]any{"type": "unknown", "t": now})
	emit(r, tb, map[string]any{"type": "hello"})
	r.onEvent(tb, &runtime.EventBindingCalled{Name: "someoneElse", Payload: `{"type":"step_end"}`})
	r.onEvent(tb, &runtime.EventBindingCalled{Name: BindingName, Payload: `not json`})

	if len(r.steps) != 2 || r.active != 1 {
		t.Fatalf("steps %+v active %d", r.steps, r.active)
	}
	want := []har.TypedInput{
		{Label: "Share name", Name: "name", Selector: "#share-name", Type: "text", Value: "media"},
		{Label: "Comment", Selector: "#c", Type: "textarea", Value: "x"},
	}
	if !reflect.DeepEqual(r.steps[0].Inputs, want) {
		t.Errorf("inputs = %+v", r.steps[0].Inputs)
	}
	if !r.steps[0].End.Equal(r.steps[1].Start) {
		t.Errorf("a new step does not end the running one: %+v", r.steps)
	}
	wantLogin := har.LoginCapture{PageURL: "http://nas.local/login?retry=1#x", UsernameSelector: "#u", PasswordSelector: "#p", SubmitSelector: "#go", Username: "admin", Password: "pw1"}
	if r.login == nil || *r.login != wantLogin {
		t.Errorf("login = %+v", r.login)
	}
	if js := r.syncScript(); !strings.Contains(js, `"step":"second"`) || !strings.Contains(js, `"steps":2`) || !strings.HasPrefix(js, "window.__har2mcp && ") {
		t.Errorf("sync script = %s", js)
	}
	emit(r, tb, map[string]any{"type": "step_end", "t": now + 20})
	if js := r.syncScript(); !strings.Contains(js, `"step":null`) {
		t.Errorf("sync script after the step = %s", js)
	}
}

func TestEventTime(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	if got := eventTime(0, now); !got.Equal(now) {
		t.Errorf("no timestamp: %v", got)
	}
	if got := eventTime(ms(now.Add(-2*time.Hour)), now); !got.Equal(now) {
		t.Errorf("far timestamp: %v", got)
	}
	if got := eventTime(ms(now.Add(-1500*time.Millisecond)), now); !got.Equal(now.Add(-1500 * time.Millisecond)) {
		t.Errorf("near timestamp: %v", got)
	}
}

func TestNameValues(t *testing.T) {
	got := nameValues(network.Headers{"b": "1", "A": "x\ny", "c": float64(5), ":authority": "nas"})
	want := []har.NameValue{{Name: ":authority", Value: "nas"}, {Name: "A", Value: "x"}, {Name: "A", Value: "y"}, {Name: "b", Value: "1"}, {Name: "c", Value: "5"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
	if nameValues(nil) != nil {
		t.Error("nil headers")
	}
	if headerValue(network.Headers{"content-TYPE": "a/b\nc/d"}, "Content-Type") != "a/b" {
		t.Error("headerValue")
	}
}

func TestFormParams(t *testing.T) {
	got := formParams("application/x-www-form-urlencoded; charset=UTF-8", []byte("a=1&b=x%20y&c&&d=%zz"))
	want := []har.Param{{Name: "a", Value: "1"}, {Name: "b", Value: "x y"}, {Name: "c"}, {Name: "d", Value: "%zz"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("urlencoded = %+v", got)
	}
	mp := "--B\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n/public\r\n" +
		"--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B--\r\n"
	got = formParams("multipart/form-data; boundary=B", []byte(mp))
	want = []har.Param{{Name: "path", Value: "/public"}, {Name: "file", FileName: "a.txt", ContentType: "text/plain"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("multipart = %+v", got)
	}
	// A body cut short keeps the parts before the cut.
	got = formParams("multipart/form-data; boundary=B", []byte(mp[:60]))
	if len(got) > 1 {
		t.Errorf("truncated multipart = %+v", got)
	}
	if formParams("application/json", []byte(`{}`)) != nil || formParams("multipart/form-data", []byte(mp)) != nil || formParams("", nil) != nil {
		t.Error("non-form bodies have params")
	}
	long := strings.Repeat("é", maxParamValue) // two bytes each
	if p := formParams("application/x-www-form-urlencoded", []byte("v="+long)); len(p[0].Value) > maxParamValue || !strings.HasPrefix(long, p[0].Value) {
		t.Errorf("long value not capped at a rune boundary: %d bytes", len(p[0].Value))
	}
}

func TestQueryPairs(t *testing.T) {
	got := queryPairs("http://h/p?b=2&a=1&a=3&bad=%zz&sp=a+b")
	want := []har.NameValue{{Name: "b", Value: "2"}, {Name: "a", Value: "1"}, {Name: "a", Value: "3"}, {Name: "bad", Value: "%zz"}, {Name: "sp", Value: "a b"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
	if queryPairs("http://h/p") != nil || queryPairs("::bad") != nil {
		t.Error("no query should give nil")
	}
}

func TestProtoName(t *testing.T) {
	for in, want := range map[string]string{"h2": "HTTP/2", "http/1.1": "HTTP/1.1", "http/1.0": "HTTP/1.0", "h3": "HTTP/3", "": "HTTP/1.1"} {
		if got := protoName(in); got != want {
			t.Errorf("protoName(%q) = %q", in, got)
		}
	}
}

func TestTimingsWithoutResourceTiming(t *testing.T) {
	rr := &reqRecord{startTS: 10, respTS: 10.2, endTS: 10.5, resp: &network.Response{Status: 200}}
	tm, total := timings(rr)
	if !near(tm.Send, 0) || !near(tm.Wait, 200) || !near(tm.Receive, 300) || !near(total, 500) {
		t.Errorf("timings %+v total %v", tm, total)
	}
	// A request that never finished has no negative phases.
	tm, total = timings(&reqRecord{startTS: 10})
	if tm.Send < 0 || tm.Wait < 0 || tm.Receive < 0 || total != 0 {
		t.Errorf("unfinished: %+v %v", tm, total)
	}
}

func TestCookieParsing(t *testing.T) {
	got := requestCookies([]har.NameValue{{Name: "cookie", Value: "a=1; b=x=y;  ;c"}})
	want := []har.Cookie{{Name: "a", Value: "1"}, {Name: "b", Value: "x=y"}, {Name: "c"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("request cookies = %+v", got)
	}
	rc := responseCookies([]har.NameValue{
		{Name: "Set-Cookie", Value: "s=1; Domain=nas.local; Path=/x; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly"},
		{Name: "Set-Cookie", Value: "=bad"},
		{Name: "Other", Value: "z=1"},
	})
	if len(rc) != 1 {
		t.Fatalf("response cookies = %+v", rc)
	}
	c := rc[0]
	if c.Name != "s" || c.Value != "1" || c.Domain != "nas.local" || c.Path != "/x" || !c.Secure || !c.HTTPOnly ||
		c.Expires == nil || !c.Expires.Equal(time.Date(2026, 10, 21, 7, 28, 0, 0, time.UTC)) {
		t.Errorf("cookie = %+v", c)
	}
}
