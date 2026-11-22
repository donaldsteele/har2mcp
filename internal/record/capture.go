package record

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chromedp/cdproto/network"
	"github.com/donaldsteele/har2mcp/internal/har"
)

const (
	// triggerWindow is how long after a click a request still counts as
	// caused by it.
	triggerWindow = 2 * time.Second
	// clockSlack absorbs the rounding between the page's millisecond clock
	// and Chrome's microsecond request times.
	clockSlack = 10 * time.Millisecond
	// maxParamValue caps the value of one form field or multipart part in
	// PostData.Params.
	maxParamValue = 64 << 10
	// maxWSMessages caps the frames kept per WebSocket.
	maxWSMessages = 10000
)

// reqRecord is one HTTP request hop. A redirect ends a hop, and the request
// continues as a new hop with the same request id.
type reqRecord struct {
	key string // tab index and request id
	hop int    // 0 for the first hop of a request id
	tab *tab
	id  network.RequestID

	start   time.Time // wall clock, from Chrome
	startTS float64   // Chrome's monotonic seconds
	method  string
	url     string
	headers network.Headers // as the page sent them; the extra info has the raw ones
	resType string

	hasPost     bool
	postData    []byte
	postOmitted bool // Chrome left the body out of the event

	resp        *network.Response
	respTS      float64
	redirectURL string

	done, failed bool
	errText      string
	endTS        float64

	dataLen        int64
	encodedBodyLen float64
	body           []byte
	bodyFetched    bool
	bodyTruncated  bool
}

// respExtra is a Network.responseReceivedExtraInfo event: the raw response
// headers, which include Set-Cookie.
type respExtra struct {
	headers     network.Headers
	status      int64
	headersText string
}

// wsRecord is one WebSocket connection.
type wsRecord struct {
	key         string
	url         string
	start       time.Time
	startTS     float64
	reqHeaders  network.Headers
	status      int64
	statusText  string
	respHeaders network.Headers
	msgs        []har.WSMessage
	closedTS    float64
}

func reqKey(t *tab, id network.RequestID) string {
	return strconv.Itoa(t.idx) + ":" + string(id)
}

func isHTTP(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

func isWS(u string) bool {
	return strings.HasPrefix(u, "ws://") || strings.HasPrefix(u, "wss://")
}

// wallTime converts Chrome's seconds since the epoch to a time.Time,
// rounded to the microsecond (the precision Chrome reports).
func wallTime(sec float64) time.Time {
	s, frac := math.Modf(sec)
	return time.Unix(int64(s), int64(math.Round(frac*1e6))*1000).UTC()
}

// requestWillBeSent starts a hop, and ends the previous hop of a redirect.
// r.mu is held.
func (r *recorder) requestWillBeSent(t *tab, e *network.EventRequestWillBeSent) {
	if e.Request == nil || !isHTTP(e.Request.URL) || e.Type == network.ResourceTypePreflight {
		return
	}
	k := reqKey(t, e.RequestID)
	if prev := r.live[k]; prev != nil && e.RedirectResponse != nil {
		prev.resp = e.RedirectResponse
		prev.respTS = float64(e.Timestamp)
		prev.redirectURL = e.Request.URL
		prev.endTS = float64(e.Timestamp)
		prev.done = true
		r.endLive(k)
	}
	rr := &reqRecord{
		key:     k,
		hop:     r.hops[k],
		tab:     t,
		id:      e.RequestID,
		start:   wallTime(float64(e.WallTime)),
		startTS: float64(e.Timestamp),
		method:  e.Request.Method,
		url:     e.Request.URL,
		headers: e.Request.Headers,
		resType: strings.ToLower(string(e.Type)),
		hasPost: e.Request.HasPostData,
	}
	r.hops[k]++
	if rr.hasPost {
		for _, pe := range e.Request.PostDataEntries {
			if pe != nil {
				rr.postData = append(rr.postData, pe.Bytes...)
			}
		}
		if len(e.Request.PostDataEntries) == 0 {
			// Chrome leaves out a body above maxPostDataSize. A multipart
			// body is fetched again for its structure (Chrome omits the
			// file contents there, so it stays small).
			rr.postOmitted = true
			if isMultipart(headerValue(rr.headers, "Content-Type")) {
				r.jobs++
				t.enqueue(job{kind: jobPostData, rr: rr})
			}
		}
	}
	r.reqs = append(r.reqs, rr)
	r.live[k] = rr
	r.inflight++
	if r.active >= 0 {
		r.stepCount++
		r.notifyTabs()
	}
}

// endLive marks the live hop of k as finished. r.mu is held.
func (r *recorder) endLive(k string) {
	if _, ok := r.live[k]; ok {
		delete(r.live, k)
		r.inflight--
	}
}

func (r *recorder) responseReceived(t *tab, e *network.EventResponseReceived) {
	rr := r.live[reqKey(t, e.RequestID)]
	if rr == nil || e.Response == nil {
		return
	}
	rr.resp = e.Response
	rr.respTS = float64(e.Timestamp)
	if rr.resType == "" {
		rr.resType = strings.ToLower(string(e.Type))
	}
}

func (r *recorder) loadingFinished(t *tab, e *network.EventLoadingFinished) {
	k := reqKey(t, e.RequestID)
	rr := r.live[k]
	if rr == nil {
		return
	}
	rr.done = true
	rr.endTS = float64(e.Timestamp)
	rr.encodedBodyLen = e.EncodedBodyLength
	if rr.encodedBodyLen == 0 {
		rr.encodedBodyLen = e.EncodedDataLength
	}
	r.endLive(k)
	if !hasBody(rr) {
		return
	}
	if rr.dataLen > r.bodyCap {
		rr.bodyTruncated = true
		return
	}
	r.jobs++
	t.enqueue(job{kind: jobBody, rr: rr})
}

// hasBody reports whether a finished hop can have a response body.
func hasBody(rr *reqRecord) bool {
	if rr.resp == nil || rr.method == http.MethodHead {
		return false
	}
	s := rr.resp.Status
	return !(s < 200 || s == http.StatusNoContent || s == http.StatusNotModified || (s >= 300 && s < 400))
}

func (r *recorder) loadingFailed(t *tab, e *network.EventLoadingFailed) {
	k := reqKey(t, e.RequestID)
	rr := r.live[k]
	if rr == nil {
		return
	}
	rr.failed = true
	rr.done = true
	rr.errText = e.ErrorText
	if rr.errText == "" && e.Canceled {
		rr.errText = "net::ERR_ABORTED"
	}
	rr.endTS = float64(e.Timestamp)
	r.endLive(k)
}

// setBody stores a fetched response body, or marks it truncated above the
// cap. r.mu is held.
//
// Chrome answers with an empty body when the page consumed the response
// without DevTools seeing the bytes (fetch(...).blob() does that). Then the
// body is left unrecorded, and the entry keeps the size the server
// announced, rather than claiming an empty response.
func (r *recorder) setBody(rr *reqRecord, body []byte) {
	if int64(len(body)) > r.bodyCap {
		rr.bodyTruncated = true
		if int64(len(body)) > rr.dataLen {
			rr.dataLen = int64(len(body))
		}
		return
	}
	if len(body) == 0 && rr.resp != nil {
		if n := contentLength(rr.resp.Headers); n > 0 {
			rr.dataLen = max(rr.dataLen, n)
			return
		}
	}
	rr.body = body
	rr.bodyFetched = true
}

// contentLength returns the Content-Length header, or -1.
func contentLength(h network.Headers) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(headerValue(h, "Content-Length")), 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// ---- WebSockets ----

func (r *recorder) wsCreated(t *tab, e *network.EventWebSocketCreated) {
	if !isWS(e.URL) {
		return
	}
	k := reqKey(t, e.RequestID)
	ws := &wsRecord{key: k, url: e.URL, start: time.Now().UTC()}
	r.sockets = append(r.sockets, ws)
	r.liveWS[k] = ws
}

func (r *recorder) wsHandshake(t *tab, e *network.EventWebSocketWillSendHandshakeRequest) {
	ws := r.liveWS[reqKey(t, e.RequestID)]
	if ws == nil {
		return
	}
	ws.start = wallTime(float64(e.WallTime))
	ws.startTS = float64(e.Timestamp)
	if e.Request != nil {
		ws.reqHeaders = e.Request.Headers
	}
}

func (r *recorder) wsHandshakeResponse(t *tab, e *network.EventWebSocketHandshakeResponseReceived) {
	ws := r.liveWS[reqKey(t, e.RequestID)]
	if ws == nil || e.Response == nil {
		return
	}
	ws.status = e.Response.Status
	ws.statusText = e.Response.StatusText
	ws.respHeaders = e.Response.Headers
	if len(e.Response.RequestHeaders) > 0 {
		ws.reqHeaders = e.Response.RequestHeaders
	}
}

func (r *recorder) wsFrame(t *tab, id network.RequestID, ts float64, f *network.WebSocketFrame, typ string) {
	ws := r.liveWS[reqKey(t, id)]
	if ws == nil || f == nil || len(ws.msgs) >= maxWSMessages {
		return
	}
	m := har.WSMessage{Type: typ, Opcode: int(f.Opcode)}
	if ws.startTS > 0 {
		m.Time = float64(ws.start.UnixNano())/1e9 + (ts - ws.startTS)
	} else {
		m.Time = float64(time.Now().UnixNano()) / 1e9
	}
	if int64(len(f.PayloadData)) <= r.bodyCap {
		if f.Opcode == 1 {
			m.Data = string(f.PayloadData)
		} else {
			m.Data = base64.StdEncoding.EncodeToString(f.PayloadData)
		}
	}
	ws.msgs = append(ws.msgs, m)
}

func (r *recorder) wsClosed(t *tab, e *network.EventWebSocketClosed) {
	k := reqKey(t, e.RequestID)
	if ws := r.liveWS[k]; ws != nil {
		ws.closedTS = float64(e.Timestamp)
		delete(r.liveWS, k)
	}
}

// ---- building the HAR ----

// buildEntries turns the recorded hops and sockets into HAR entries in start
// order, with _step and _trigger set. r.mu is held.
func (r *recorder) buildEntries(steps []har.Step) []har.Entry {
	entries := make([]har.Entry, 0, len(r.reqs)+len(r.sockets))
	for _, rr := range r.reqs {
		entries = append(entries, r.httpEntry(rr))
	}
	for _, ws := range r.sockets {
		entries = append(entries, r.wsEntry(ws))
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].StartedDateTime.Before(entries[j].StartedDateTime)
	})
	for i := range entries {
		e := &entries[i]
		e.Step = stepAt(steps, e.StartedDateTime)
		e.Trigger = triggerAt(r.clicks, e.StartedDateTime)
	}
	return entries
}

// stepAt returns the name of the step running at time at, or "".
func stepAt(steps []har.Step, at time.Time) string {
	for _, s := range steps {
		if !at.Before(s.Start) && (s.End.IsZero() || at.Before(s.End)) {
			return s.Name
		}
	}
	return ""
}

// triggerAt returns the last click at most triggerWindow before at.
func triggerAt(clicks []click, at time.Time) *har.Trigger {
	for i := len(clicks) - 1; i >= 0; i-- {
		c := clicks[i]
		if c.at.After(at.Add(clockSlack)) {
			continue
		}
		if at.Sub(c.at) > triggerWindow {
			return nil
		}
		tr := c.trigger
		return &tr
	}
	return nil
}

func (r *recorder) httpEntry(rr *reqRecord) har.Entry {
	reqHeaders := rr.headers
	if ex := r.reqExtra[rr.key]; rr.hop < len(ex) && len(ex[rr.hop]) > 0 {
		reqHeaders = ex[rr.hop]
	}
	var (
		respHeaders network.Headers
		status      int64
		statusText  string
		proto       string
		mimeType    string
		headersText string
	)
	if rr.resp != nil {
		respHeaders = rr.resp.Headers
		status = rr.resp.Status
		statusText = rr.resp.StatusText
		proto = rr.resp.Protocol
		mimeType = rr.resp.MimeType
	}
	if ex := r.respExtra[rr.key]; rr.hop < len(ex) {
		if len(ex[rr.hop].headers) > 0 {
			respHeaders = ex[rr.hop].headers
		}
		if status == 0 {
			status = ex[rr.hop].status
		}
		headersText = ex[rr.hop].headersText
	}
	if rr.failed && rr.resp == nil {
		status, statusText = 0, rr.errText
	} else if statusText == "" && status > 0 {
		statusText = http.StatusText(int(status))
	}
	httpVersion := protoName(proto)

	req := har.Request{
		Method:      rr.method,
		URL:         rr.url,
		HTTPVersion: httpVersion,
		Headers:     nameValues(reqHeaders),
		QueryString: queryPairs(rr.url),
		HeadersSize: -1,
	}
	req.Cookies = requestCookies(req.Headers)
	if rr.hasPost {
		ct := headerValue(reqHeaders, "Content-Type")
		pd := &har.PostData{MimeType: ct, Params: formParams(ct, rr.postData)}
		size := int64(len(rr.postData))
		// Chrome leaves file contents out of a multipart body, so the
		// announced length is the better size.
		size = max(size, contentLength(reqHeaders))
		if !rr.postOmitted && int64(len(rr.postData)) <= r.bodyCap {
			pd.Text = strings.ToValidUTF8(string(rr.postData), "\uFFFD")
		}
		req.PostData = pd
		req.BodySize = size
	}

	resp := har.Response{
		Status:      int(status),
		StatusText:  statusText,
		HTTPVersion: httpVersion,
		Headers:     nameValues(respHeaders),
		RedirectURL: rr.redirectURL,
		HeadersSize: -1,
	}
	if headersText != "" {
		resp.HeadersSize = int64(len(headersText))
	}
	resp.Cookies = responseCookies(resp.Headers)
	ct := headerValue(respHeaders, "Content-Type")
	if ct == "" {
		ct = mimeType
	}
	resp.Content = har.Content{MimeType: ct, Size: rr.dataLen}
	switch {
	case rr.bodyTruncated:
		resp.Content.Truncated = true
	case rr.bodyFetched:
		resp.Content.Size = int64(len(rr.body))
		if utf8.Valid(rr.body) {
			resp.Content.Text = string(rr.body)
		} else {
			resp.Content.Text = base64.StdEncoding.EncodeToString(rr.body)
			resp.Content.Encoding = "base64"
		}
	}
	switch {
	case rr.encodedBodyLen > 0:
		resp.BodySize = int64(rr.encodedBodyLen)
	case rr.bodyFetched:
		resp.BodySize = int64(len(rr.body))
	}

	e := har.Entry{
		StartedDateTime: rr.start,
		Request:         req,
		Response:        resp,
		ResourceType:    rr.resType,
	}
	e.Timings, e.Time = timings(rr)
	return e
}

// timings splits a hop's duration into HAR send, wait and receive phases in
// milliseconds. wait takes whatever the other two do not cover, so the three
// add up to the total.
func timings(rr *reqRecord) (har.Timings, float64) {
	end := rr.endTS
	if end == 0 {
		end = rr.respTS
	}
	total := 0.0
	if end > rr.startTS && rr.startTS > 0 {
		total = (end - rr.startTS) * 1000
	}
	var t har.Timings
	if rr.resp != nil && rr.resp.Timing != nil {
		tm := rr.resp.Timing
		t.Send = math.Max(0, tm.SendEnd-tm.SendStart)
		if rr.endTS > 0 && tm.RequestTime > 0 {
			t.Receive = math.Max(0, (rr.endTS-tm.RequestTime)*1000-tm.ReceiveHeadersEnd)
		}
	} else if rr.respTS > 0 && rr.endTS > rr.respTS {
		t.Receive = (rr.endTS - rr.respTS) * 1000
	}
	if t.Send+t.Receive > total {
		total = t.Send + t.Receive
	}
	t.Wait = total - t.Send - t.Receive
	return t, t.Send + t.Wait + t.Receive
}

func (r *recorder) wsEntry(ws *wsRecord) har.Entry {
	req := har.Request{
		Method:      http.MethodGet,
		URL:         ws.url,
		HTTPVersion: "HTTP/1.1",
		Headers:     nameValues(ws.reqHeaders),
		QueryString: queryPairs(ws.url),
		HeadersSize: -1,
	}
	req.Cookies = requestCookies(req.Headers)
	statusText := ws.statusText
	if statusText == "" && ws.status > 0 {
		statusText = http.StatusText(int(ws.status))
	}
	resp := har.Response{
		Status:      int(ws.status),
		StatusText:  statusText,
		HTTPVersion: "HTTP/1.1",
		Headers:     nameValues(ws.respHeaders),
		Content:     har.Content{MimeType: "x-unknown"},
		HeadersSize: -1,
	}
	resp.Cookies = responseCookies(resp.Headers)
	e := har.Entry{
		StartedDateTime:   ws.start,
		Request:           req,
		Response:          resp,
		ResourceType:      "websocket",
		WebSocketMessages: slices.Clone(ws.msgs),
	}
	if ws.closedTS > ws.startTS && ws.startTS > 0 {
		e.Time = (ws.closedTS - ws.startTS) * 1000
		e.Timings.Wait = e.Time
	}
	return e
}

// protoName turns Chrome's protocol name into a HAR httpVersion.
func protoName(p string) string {
	switch strings.ToLower(p) {
	case "h2", "http/2", "http/2.0":
		return "HTTP/2"
	case "h3", "http/3", "quic", "h3-29":
		return "HTTP/3"
	case "http/1.0":
		return "HTTP/1.0"
	default:
		return "HTTP/1.1"
	}
}

// nameValues turns DevTools headers into HAR headers, sorted by name. A
// value Chrome joined with "\n" (repeated headers such as Set-Cookie) becomes
// one entry per line.
func nameValues(h network.Headers) []har.NameValue {
	if len(h) == 0 {
		return nil
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := strings.ToLower(keys[i]), strings.ToLower(keys[j])
		if a != b {
			return a < b
		}
		return keys[i] < keys[j]
	})
	out := make([]har.NameValue, 0, len(keys))
	for _, k := range keys {
		var v string
		switch x := h[k].(type) {
		case string:
			v = x
		case nil:
		default:
			v = fmt.Sprint(x)
		}
		for line := range strings.SplitSeq(v, "\n") {
			out = append(out, har.NameValue{Name: k, Value: line})
		}
	}
	return out
}

// headerValue returns the first value of a header, compared
// case-insensitively.
func headerValue(h network.Headers, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			s, _ := v.(string)
			first, _, _ := strings.Cut(s, "\n")
			return first
		}
	}
	return ""
}

func requestCookies(headers []har.NameValue) []har.Cookie {
	var out []har.Cookie
	for _, h := range headers {
		if !strings.EqualFold(h.Name, "Cookie") {
			continue
		}
		for part := range strings.SplitSeq(h.Value, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok && name == "" {
				continue
			}
			out = append(out, har.Cookie{Name: name, Value: value})
		}
	}
	return out
}

func responseCookies(headers []har.NameValue) []har.Cookie {
	var out []har.Cookie
	for _, h := range headers {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		c, err := http.ParseSetCookie(h.Value)
		if err != nil {
			continue
		}
		hc := har.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Domain: c.Domain, HTTPOnly: c.HttpOnly, Secure: c.Secure}
		if !c.Expires.IsZero() {
			exp := c.Expires.UTC()
			hc.Expires = &exp
		} else if c.MaxAge > 0 {
			exp := time.Now().Add(time.Duration(c.MaxAge) * time.Second).UTC().Truncate(time.Second)
			hc.Expires = &exp
		}
		out = append(out, hc)
	}
	return out
}

// queryPairs returns a URL's query string in order, decoded.
func queryPairs(rawURL string) []har.NameValue {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	return formPairs(u.RawQuery)
}

// formPairs splits an application/x-www-form-urlencoded string, keeping the
// order and keeping a part raw when it does not decode.
func formPairs(s string) []har.NameValue {
	var out []har.NameValue
	for part := range strings.SplitSeq(s, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		out = append(out, har.NameValue{Name: k, Value: v})
	}
	return out
}

func isMultipart(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "multipart/form-data"
}

// formParams lists the fields of a form body: each pair of a URL-encoded
// body, or each part of a multipart body with its name, file name and
// content type. A file part has no value; other values are capped.
func formParams(contentType string, body []byte) []har.Param {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil
	}
	switch mt {
	case "application/x-www-form-urlencoded":
		var out []har.Param
		for _, p := range formPairs(string(body)) {
			out = append(out, har.Param{Name: p.Name, Value: capValue(p.Value)})
		}
		return out
	case "multipart/form-data":
		boundary := params["boundary"]
		if boundary == "" {
			return nil
		}
		var out []har.Param
		mr := multipart.NewReader(bytes.NewReader(body), boundary)
		for {
			part, err := mr.NextRawPart()
			if err != nil {
				break
			}
			p := har.Param{Name: part.FormName(), FileName: part.FileName(), ContentType: part.Header.Get("Content-Type")}
			if p.FileName == "" && part.Header.Get("Content-Disposition") != "" && !strings.Contains(part.Header.Get("Content-Disposition"), "filename") {
				b, _ := io.ReadAll(io.LimitReader(part, maxParamValue+1))
				p.Value = capValue(strings.ToValidUTF8(string(b), "\uFFFD"))
			}
			out = append(out, p)
		}
		return out
	}
	return nil
}

func capValue(v string) string {
	if len(v) > maxParamValue {
		return strings.ToValidUTF8(v[:maxParamValue], "")
	}
	return v
}
