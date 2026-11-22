package analyze

import (
	"bytes"
	"encoding/json"
	"mime"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/donaldsteele/har2mcp/internal/har"
)

// pickHosts returns the hosts to analyze: the ones given (normalized), else
// the start URL hosts of the recordings and the hosts their redirects led
// to (http://tplinkwifi.net -> http://192.168.0.1), else the host most XHR
// and fetch calls went to.
func pickHosts(rec *recording, given []string) []string {
	var hosts []string
	seen := map[string]bool{}
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	if len(given) > 0 {
		for _, g := range given {
			g = strings.TrimSpace(g)
			if strings.Contains(g, "://") {
				if u, err := url.Parse(g); err == nil {
					g = u.Host
				}
			}
			g, _, _ = strings.Cut(g, "/")
			add(g)
		}
		return hosts
	}
	for _, h := range rec.hars {
		if m := h.Log.Har2mcp; m != nil && m.StartURL != "" {
			if u, err := url.Parse(m.StartURL); err == nil && u.Hostname() != "" {
				add(u.Hostname())
				for _, r := range redirectChain(h, u) {
					add(r.Hostname())
				}
			}
		}
	}
	if len(hosts) > 0 {
		return hosts
	}
	return busiestHosts(rec)
}

// redirectChain follows the redirects recorded for start: each entry for
// the current URL with a 3xx status and a redirect target leads to the
// next. It returns the URLs the redirects led to.
func redirectChain(h *har.HAR, start *url.URL) []*url.URL {
	var out []*url.URL
	cur := start
	for n := 0; n < 10; n++ {
		var next *url.URL
		for i := range h.Log.Entries {
			e := &h.Log.Entries[i]
			if e.Response.Status < 300 || e.Response.Status > 399 {
				continue
			}
			u, err := url.Parse(e.Request.URL)
			if err != nil || !sameURL(u, cur) {
				continue
			}
			loc := e.Response.RedirectURL
			if loc == "" {
				loc = e.Response.Header("Location")
			}
			if t, err := cur.Parse(loc); err == nil && loc != "" && t.Hostname() != "" {
				next = t
				break
			}
		}
		if next == nil || sameURL(next, cur) {
			break
		}
		out = append(out, next)
		cur = next
	}
	return out
}

// sameURL reports whether two URLs have the same scheme, host and path
// ("" and "/" count as the same path).
func sameURL(a, b *url.URL) bool {
	pa, pb := a.EscapedPath(), b.EscapedPath()
	if pa == "" {
		pa = "/"
	}
	if pb == "" {
		pb = "/"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host) && pa == pb
}

// hostMatchesAny reports whether any of hosts matches one of others.
func hostMatchesAny(hosts, others []string) bool {
	for _, h := range hosts {
		u := &url.URL{Host: h}
		if hostMatches(u, others) {
			return true
		}
	}
	return false
}

// navigatedHosts returns, as a one-element list, the host that most API
// calls went to among the hosts the browser loaded a page from, or nil.
// Third-party hosts such as analytics get calls but no page load, so they
// are never picked.
func navigatedHosts(rec *recording) []string {
	pages := map[string]bool{}
	for _, s := range rec.samples {
		rt := strings.ToLower(s.e.ResourceType)
		if rt == "document" || (rt == "" && strings.EqualFold(s.e.Request.Method, "GET") && responseMIME(s.e) == "text/html") {
			pages[strings.ToLower(s.u.Hostname())] = true
		}
	}
	count := map[string]int{}
	best := ""
	for _, s := range rec.samples {
		h := strings.ToLower(s.u.Hostname())
		if !pages[h] || isStatic(s) {
			continue
		}
		count[h]++
		if best == "" || count[h] > count[best] {
			best = h
		}
	}
	if best == "" {
		return nil
	}
	return []string{best}
}

// busiestHosts returns the host most XHR and fetch calls went to (most
// non-static requests when the HAR does not say which are XHR), as a
// one-element list, or nil when there are no requests.
func busiestHosts(rec *recording) []string {
	var hosts []string
	count := map[string]int{}
	first := map[string]int{}
	tally := func(s *sample) {
		h := strings.ToLower(s.u.Hostname())
		if _, ok := first[h]; !ok {
			first[h] = s.seq
		}
		count[h]++
	}
	for _, s := range rec.samples {
		if rt := strings.ToLower(s.e.ResourceType); rt == "xhr" || rt == "fetch" {
			tally(s)
		}
	}
	if len(count) == 0 {
		for _, s := range rec.samples {
			if !isStatic(s) {
				tally(s)
			}
		}
	}
	var cands []string
	for h := range count {
		cands = append(cands, h)
	}
	sort.Slice(cands, func(i, j int) bool {
		if count[cands[i]] != count[cands[j]] {
			return count[cands[i]] > count[cands[j]]
		}
		return first[cands[i]] < first[cands[j]]
	})
	if len(cands) > 0 && cands[0] != "" {
		hosts = append(hosts, cands[0])
	}
	return hosts
}

// hostMatches reports whether u is on one of hosts. A host with a port must
// match host and port; a host without one matches any port.
func hostMatches(u *url.URL, hosts []string) bool {
	for _, h := range hosts {
		if hasPort(h) {
			if strings.EqualFold(u.Host, h) {
				return true
			}
			continue
		}
		if strings.EqualFold(u.Hostname(), strings.Trim(h, "[]")) {
			return true
		}
	}
	return false
}

func hasPort(h string) bool {
	if strings.HasPrefix(h, "[") {
		return strings.Contains(h, "]:")
	}
	return strings.Count(h, ":") == 1
}

// hostOnly strips a port and IPv6 brackets.
func hostOnly(h string) string {
	if hasPort(h) {
		if host, _, err := net.SplitHostPort(h); err == nil {
			return host
		}
	}
	return strings.Trim(h, "[]")
}

func isIP(h string) bool { return net.ParseIP(strings.Trim(h, "[]")) != nil }

var staticResourceTypes = map[string]bool{
	"stylesheet": true, "image": true, "media": true, "font": true, "script": true,
	"texttrack": true, "prefetch": true, "eventsource": true, "websocket": true,
	"manifest": true, "signedexchange": true, "ping": true, "cspviolationreport": true,
	"preflight": true, "fedcm": true,
}

var staticExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true,
	".webp": true, ".avif": true, ".bmp": true, ".css": true, ".js": true, ".mjs": true,
	".map": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".html": true, ".htm": true, ".mp4": true, ".webm": true, ".mp3": true, ".wav": true,
	".ogg": true, ".wasm": true,
}

// isStatic reports whether a request is something analysis ignores: a page,
// script, stylesheet, image, font, CORS preflight or WebSocket upgrade.
// Attachments and binary downloads are never static.
func isStatic(s *sample) bool {
	e := s.e
	if isAttachment(e) {
		return false
	}
	if strings.EqualFold(e.Request.Method, "OPTIONS") || e.Response.Status == 101 {
		return true
	}
	m := responseMIME(e)
	switch rt := strings.ToLower(e.ResourceType); {
	case rt == "xhr" || rt == "fetch":
		// A script fetching a template or stylesheet is still static.
		return strings.EqualFold(e.Request.Method, "GET") && isStaticMIME(m) && !bodyLooksLikeData(e)
	case rt == "document":
		return !isBinaryDownload(e)
	case staticResourceTypes[rt]:
		return true
	}
	if isBinaryDownload(e) {
		return false
	}
	if staticExtensions[strings.ToLower(path.Ext(s.u.Path))] && !bodyLooksLikeData(e) {
		return true
	}
	if isStaticMIME(m) && !bodyLooksLikeData(e) {
		return true
	}
	return false
}

// responseMIME is the response media type in lower case, without
// parameters.
func responseMIME(e *har.Entry) string {
	m := e.Response.Content.MimeType
	if m == "" {
		m = e.Response.Header("Content-Type")
	}
	return mediaType(m)
}

func mediaType(m string) string {
	m = strings.TrimSpace(m)
	if m == "" {
		return ""
	}
	if t, _, err := mime.ParseMediaType(m); err == nil {
		return strings.ToLower(t)
	}
	t, _, _ := strings.Cut(m, ";")
	return strings.ToLower(strings.TrimSpace(t))
}

func isStaticMIME(m string) bool {
	switch {
	case strings.HasPrefix(m, "image/"), strings.HasPrefix(m, "font/"),
		strings.HasPrefix(m, "audio/"), strings.HasPrefix(m, "video/"),
		strings.HasPrefix(m, "application/font-"), strings.HasPrefix(m, "application/x-font-"):
		return true
	}
	switch m {
	case "text/css", "text/javascript", "application/javascript", "application/x-javascript",
		"application/ecmascript", "text/html", "application/xhtml+xml", "application/wasm",
		"application/manifest+json", "text/cache-manifest", "application/vnd.ms-fontobject":
		return true
	}
	return false
}

func isAttachment(e *har.Entry) bool {
	return strings.Contains(strings.ToLower(e.Response.Header("Content-Disposition")), "attachment")
}

var binaryMIMEs = map[string]bool{
	"application/octet-stream": true, "application/zip": true, "application/x-zip-compressed": true,
	"application/gzip": true, "application/x-gzip": true, "application/x-tar": true,
	"application/x-7z-compressed": true, "application/x-rar-compressed": true, "application/vnd.rar": true,
	"application/x-bzip2": true, "application/x-xz": true, "application/pdf": true,
	"application/x-download": true, "application/force-download": true, "application/x-binary": true,
	"application/x-msdownload": true, "application/binary": true,
}

// isBinaryDownload reports whether a response is a file download: an
// attachment, or a binary type whose body is not JSON or XML.
func isBinaryDownload(e *har.Entry) bool {
	if e.Response.Status < 200 || e.Response.Status >= 300 {
		return false
	}
	if isAttachment(e) {
		return true
	}
	m := responseMIME(e)
	if binaryMIMEs[m] || strings.HasPrefix(m, "application/vnd.") && !strings.Contains(m, "json") && !strings.Contains(m, "xml") {
		return !bodyLooksLikeData(e)
	}
	return false
}

// bodyLooksLikeData reports whether a response body is JSON or XML, whatever
// its declared type (PHP backends often send JSON as text/html).
func bodyLooksLikeData(e *har.Entry) bool {
	if e.Response.Content.Truncated {
		return false
	}
	b, err := e.Response.Content.Bytes()
	if err != nil {
		return false
	}
	t := bytes.TrimSpace(b)
	if len(t) == 0 {
		return false
	}
	if t[0] == '{' || t[0] == '[' {
		return json.Valid(t)
	}
	return bytes.HasPrefix(t, []byte("<?xml"))
}

// responseJSON decodes a JSON response body (numbers as json.Number).
func responseJSON(e *har.Entry) (any, bool) {
	if e.Response.Content.Truncated {
		return nil, false
	}
	b, err := e.Response.Content.Bytes()
	if err != nil {
		return nil, false
	}
	return decodeJSON(b)
}

// decodeJSON decodes a JSON object or array.
func decodeJSON(b []byte) (any, bool) {
	t := bytes.TrimSpace(b)
	if len(t) == 0 || (t[0] != '{' && t[0] != '[') {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(t))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return nil, false
	}
	return v, true
}

// walkStrings calls fn with every string in a decoded JSON value.
func walkStrings(v any, fn func(string)) {
	switch x := v.(type) {
	case string:
		fn(x)
	case map[string]any:
		for _, val := range x {
			walkStrings(val, fn)
		}
	case []any:
		for _, val := range x {
			walkStrings(val, fn)
		}
	}
}
