package har

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Redact returns a deep copy of h with secrets replaced by Redacted. h is not
// modified. These are removed:
//
//   - the Cookie, Set-Cookie and Authorization headers, and every header whose
//     name contains token, csrf, session, auth, secret, password or an
//     API-key word (case-insensitive; see IsSecretHeader)
//   - every cookie value
//   - the captured login password and every typed input that holds a secret
//     (a password field, or one labeled as a password, key, PSK or PIN; see
//     IsSecretInput)
//   - those passwords wherever they appear in URLs, query strings, bodies
//     and headers, raw or URL- or JSON-encoded. A short or common password,
//     such as "admin", is also an ordinary word in paths and values, so it
//     is removed only where a whole value equals it (see Distinctive).
//   - JSON body fields (request, response and WebSocket, any depth, any case),
//     form fields and query parameters with a secret name: password, token,
//     csrf, sid, stok, pin, psk and the like (see IsSecretField)
//   - the values found in all of the above (session ids, CSRF tokens, bearer
//     tokens) wherever else they appear, when they look like secrets: at least
//     6 characters with a digit, or at least 12 characters
//   - session tokens whatever their name: a value a response handed out that
//     a later request sends back in its URL path or a header (an OpenWrt
//     ";stok=<token>" path segment, a token from an XML response sent in a
//     header), or, for text, XML and HTML responses, anywhere in a later
//     request
func Redact(h *HAR) *HAR {
	if h == nil {
		return nil
	}
	out := copyHAR(h)
	r := &redactor{secrets: map[string]bool{}, weak: map[string]bool{}}
	r.collect(out)
	r.apply(out)
	return out
}

type redactor struct {
	secrets map[string]bool // removed wherever they appear
	weak    map[string]bool // short or common passwords: removed where a whole value equals them
	list    []string        // secrets, longest first
}

func (r *redactor) addAlways(v string) {
	if v == "" || v == Redacted {
		return
	}
	r.secrets[v] = true
	r.secrets[url.QueryEscape(v)] = true
	r.secrets[url.PathEscape(v)] = true
	if b, err := json.Marshal(v); err == nil {
		r.secrets[string(b[1:len(b)-1])] = true
	}
}

// addPassword records a password: everywhere when it is distinctive, else
// only as a whole value.
func (r *redactor) addPassword(v string) {
	if v == "" || v == Redacted {
		return
	}
	if Distinctive(v) {
		r.addAlways(v)
		return
	}
	r.weak[v] = true
}

func (r *redactor) addFound(v string) {
	v = strings.TrimSpace(v)
	if LooksSecret(v) {
		r.addAlways(v)
	}
}

// collect gathers every secret value in h before anything is changed.
func (r *redactor) collect(h *HAR) {
	if m := h.Log.Har2mcp; m != nil {
		if m.Login != nil {
			r.addPassword(m.Login.Password)
		}
		for _, s := range m.Steps {
			for _, in := range s.Inputs {
				if IsSecretInput(in) {
					r.addPassword(in.Value)
				}
			}
		}
	}
	for _, e := range h.Log.Entries {
		r.collectHeaders(e.Request.Headers)
		r.collectHeaders(e.Response.Headers)
		for _, c := range e.Request.Cookies {
			r.addFound(c.Value)
		}
		for _, c := range e.Response.Cookies {
			r.addFound(c.Value)
		}
		for _, q := range e.Request.QueryString {
			if IsSecretField(q.Name) {
				r.addFound(q.Value)
				if IsPasswordField(q.Name) {
					r.addPassword(q.Value)
				}
			}
		}
		if pd := e.Request.PostData; pd != nil {
			for _, p := range pd.Params {
				if IsSecretField(p.Name) {
					r.addFound(p.Value)
					if IsPasswordField(p.Name) {
						r.addPassword(p.Value)
					}
				}
			}
			r.collectBody([]byte(pd.Text), pd.MimeType)
		}
		if b, err := e.Response.Content.Bytes(); err == nil {
			r.collectBody(b, e.Response.Content.MimeType)
		}
		for _, m := range e.WebSocketMessages {
			r.collectBody([]byte(m.Data), "")
		}
	}
	r.collectReturnedTokens(h)
	for s := range r.secrets {
		r.list = append(r.list, s)
	}
	sort.Slice(r.list, func(i, j int) bool {
		if len(r.list[i]) != len(r.list[j]) {
			return len(r.list[i]) > len(r.list[j])
		}
		return r.list[i] < r.list[j]
	})
}

// tokenRE finds the token-like words in a text: runs of letters, digits,
// "-" and "_".
var tokenRE = regexp.MustCompile(`[A-Za-z0-9_-]{8,}`)

// maxTokenScan bounds how much of one response body is searched for tokens.
const maxTokenScan = 1 << 20

// collectReturnedTokens finds session tokens by how they are used rather
// than by name: values a response handed out that a later request sends
// back. A value from a JSON response counts when it comes back in a URL
// path segment (whole, or after "=" as in ";stok=<token>") or a header,
// because JSON responses also list items whose ids later requests send in
// their bodies. A value from a text, XML or HTML response counts wherever
// it comes back.
func (r *redactor) collectReturnedTokens(h *HAR) {
	order := make([]int, len(h.Log.Entries))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return h.Log.Entries[order[a]].StartedDateTime.Before(h.Log.Entries[order[b]].StartedDateTime)
	})
	type origin struct{ text bool }
	seen := map[string]origin{}
	for _, i := range order {
		e := &h.Log.Entries[i]
		if len(seen) > 0 {
			for _, v := range pathAndHeaderValues(e) {
				if _, ok := seen[v]; ok {
					r.addFound(v)
				}
			}
			for _, v := range otherRequestValues(e) {
				if o, ok := seen[v]; ok && o.text {
					r.addFound(v)
				}
			}
		}
		if e.Response.Content.Truncated {
			continue
		}
		b, err := e.Response.Content.Bytes()
		if err != nil || len(b) == 0 || len(b) > maxTokenScan {
			continue
		}
		if v, ok := parseJSON(b); ok {
			walkStringLeaves(v, func(s string) {
				for _, t := range append([]string{s}, tokenRE.FindAllString(s, -1)...) {
					if tokenish(t) {
						if _, dup := seen[t]; !dup {
							seen[t] = origin{}
						}
					}
				}
			})
			continue
		}
		if !utf8.Valid(b) {
			continue
		}
		for _, t := range tokenRE.FindAllString(string(b), -1) {
			if tokenish(t) {
				seen[t] = origin{text: true}
			}
		}
	}
}

// pathAndHeaderValues lists the values a request sends in its URL path
// segments (whole, and the part after the last "=") and its headers (whole,
// and the part after the last space, as in "Bearer <token>").
func pathAndHeaderValues(e *Entry) []string {
	var out []string
	if u, err := url.Parse(e.Request.URL); err == nil {
		for _, seg := range strings.Split(u.EscapedPath(), "/") {
			if s, err := url.PathUnescape(seg); err == nil {
				seg = s
			}
			out = append(out, seg)
			if i := strings.LastIndexByte(seg, '='); i >= 0 {
				out = append(out, seg[i+1:])
			}
		}
	}
	for _, h := range e.Request.Headers {
		v := strings.TrimSpace(h.Value)
		out = append(out, v)
		if i := strings.LastIndexByte(v, ' '); i >= 0 {
			out = append(out, v[i+1:])
		}
	}
	return out
}

// otherRequestValues lists the token-like words in a request's query string
// and body.
func otherRequestValues(e *Entry) []string {
	var out []string
	if u, err := url.Parse(e.Request.URL); err == nil && u.RawQuery != "" {
		if q, err := url.QueryUnescape(u.RawQuery); err == nil {
			out = append(out, tokenRE.FindAllString(q, -1)...)
		}
	}
	if pd := e.Request.PostData; pd != nil {
		text := pd.Text
		if len(text) > maxTokenScan {
			text = text[:maxTokenScan]
		}
		if u, err := url.QueryUnescape(text); err == nil {
			text = u
		}
		out = append(out, tokenRE.FindAllString(text, -1)...)
		for _, p := range pd.Params {
			out = append(out, tokenRE.FindAllString(p.Value, -1)...)
		}
	}
	return out
}

// walkStringLeaves calls fn with every string in a decoded JSON value.
func walkStringLeaves(v any, fn func(string)) {
	switch x := v.(type) {
	case string:
		fn(x)
	case map[string]any:
		for _, val := range x {
			walkStringLeaves(val, fn)
		}
	case []any:
		for _, val := range x {
			walkStringLeaves(val, fn)
		}
	}
}

func (r *redactor) collectHeaders(hs []NameValue) {
	for _, h := range hs {
		if !IsSecretHeader(h.Name) {
			continue
		}
		switch strings.ToLower(h.Name) {
		case "cookie":
			for _, pair := range strings.Split(h.Value, ";") {
				if _, v, ok := strings.Cut(pair, "="); ok {
					r.addFound(v)
				}
			}
		case "set-cookie":
			for _, line := range strings.Split(h.Value, "\n") {
				first, _, _ := strings.Cut(line, ";")
				if _, v, ok := strings.Cut(first, "="); ok {
					r.addFound(v)
				}
			}
		default:
			r.addFound(h.Value)
			if i := strings.LastIndexByte(strings.TrimSpace(h.Value), ' '); i >= 0 {
				r.addFound(strings.TrimSpace(h.Value)[i+1:])
			}
		}
	}
}

func (r *redactor) collectBody(b []byte, mime string) {
	if v, ok := parseJSON(b); ok {
		walkSecretFields(v, func(name, s string) {
			r.addFound(s)
			if IsPasswordField(name) {
				r.addPassword(s)
			}
		})
		return
	}
	if isForm(mime) {
		for _, pair := range strings.Split(string(b), "&") {
			k, v, _ := strings.Cut(pair, "=")
			if name, err := url.QueryUnescape(k); err == nil && IsSecretField(name) {
				if val, err := url.QueryUnescape(v); err == nil {
					r.addFound(val)
					if IsPasswordField(name) {
						r.addPassword(val)
					}
				}
			}
		}
	}
}

func (r *redactor) scrub(s string) string {
	if s == "" {
		return s
	}
	for _, sec := range r.list {
		if strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, Redacted)
		}
	}
	return s
}

// value redacts one whole value: a weak password it equals, and secrets
// inside it.
func (r *redactor) value(s string) string {
	if r.weak[s] {
		return Redacted
	}
	return r.scrub(s)
}

// scrubURL removes secrets from a URL, and weak passwords from its query
// values. Path segments keep weak passwords, which are ordinary words there
// ("/admin/login").
func (r *redactor) scrubURL(raw string) string {
	raw = r.scrub(raw)
	if len(r.weak) == 0 {
		return raw
	}
	base, query, ok := strings.Cut(raw, "?")
	if !ok {
		return raw
	}
	frag := ""
	if i := strings.IndexByte(query, '#'); i >= 0 {
		query, frag = query[:i], query[i:]
	}
	pairs := strings.Split(query, "&")
	for i, pair := range pairs {
		k, v, hasValue := strings.Cut(pair, "=")
		if val, err := url.QueryUnescape(v); err == nil && hasValue && r.weak[val] {
			pairs[i] = k + "=" + Redacted
		}
	}
	return base + "?" + strings.Join(pairs, "&") + frag
}

func (r *redactor) apply(h *HAR) {
	if m := h.Log.Har2mcp; m != nil {
		m.StartURL = r.scrubURL(m.StartURL)
		if m.Login != nil {
			if m.Login.Password != "" {
				m.Login.Password = Redacted
			}
			m.Login.PageURL = r.scrubURL(m.Login.PageURL)
		}
		for i := range m.Steps {
			for j := range m.Steps[i].Inputs {
				in := &m.Steps[i].Inputs[j]
				if IsSecretInput(*in) && in.Value != "" {
					in.Value = Redacted
				} else {
					in.Value = r.value(in.Value)
				}
			}
		}
	}
	for i := range h.Log.Entries {
		e := &h.Log.Entries[i]
		req, resp := &e.Request, &e.Response
		req.URL = r.scrubURL(req.URL)
		r.applyHeaders(req.Headers)
		r.applyHeaders(resp.Headers)
		for j := range req.Cookies {
			req.Cookies[j].Value = Redacted
		}
		for j := range resp.Cookies {
			resp.Cookies[j].Value = Redacted
		}
		for j := range req.QueryString {
			q := &req.QueryString[j]
			if IsSecretField(q.Name) {
				q.Value = Redacted
			} else {
				q.Value = r.value(q.Value)
			}
		}
		if pd := req.PostData; pd != nil {
			for j := range pd.Params {
				p := &pd.Params[j]
				if IsSecretField(p.Name) {
					p.Value = Redacted
				} else {
					p.Value = r.value(p.Value)
				}
			}
			pd.Text = string(r.redactBody([]byte(pd.Text), pd.MimeType))
		}
		resp.RedirectURL = r.scrubURL(resp.RedirectURL)
		if b, err := resp.Content.Bytes(); err == nil && len(b) > 0 {
			nb := r.redactBody(b, resp.Content.MimeType)
			if !bytes.Equal(nb, b) {
				if strings.EqualFold(resp.Content.Encoding, "base64") {
					resp.Content.Text = base64.StdEncoding.EncodeToString(nb)
				} else {
					resp.Content.Text = string(nb)
				}
			}
		}
		for j := range e.WebSocketMessages {
			m := &e.WebSocketMessages[j]
			m.Data = string(r.redactBody([]byte(m.Data), ""))
		}
	}
}

func (r *redactor) applyHeaders(hs []NameValue) {
	for i := range hs {
		if IsSecretHeader(hs[i].Name) {
			hs[i].Value = Redacted
		} else {
			hs[i].Value = r.value(hs[i].Value)
		}
	}
}

// redactBody redacts secret-named fields and weak-password values of a JSON
// or form body, then scrubs known secret values from what is left. Other
// bodies are only scrubbed.
func (r *redactor) redactBody(b []byte, mime string) []byte {
	if v, ok := parseJSON(b); ok {
		if nv, changed := r.redactJSON(v); changed {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(nv); err == nil {
				b = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
			}
		}
	} else if isForm(mime) {
		pairs := strings.Split(string(b), "&")
		for i, pair := range pairs {
			k, v, hasValue := strings.Cut(pair, "=")
			if !hasValue {
				continue
			}
			name, err := url.QueryUnescape(k)
			if err != nil {
				continue
			}
			val, _ := url.QueryUnescape(v)
			if IsSecretField(name) || r.weak[val] {
				pairs[i] = k + "=" + Redacted
			}
		}
		b = []byte(strings.Join(pairs, "&"))
	}
	return []byte(r.scrub(string(b)))
}

func isForm(mime string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(mime)), "application/x-www-form-urlencoded")
}

// parseJSON decodes b when it is a JSON object or array.
func parseJSON(b []byte) (any, bool) {
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

// walkSecretFields calls fn with the name and value of every string or
// number found under a secret field name.
func walkSecretFields(v any, fn func(name, value string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if IsSecretField(k) {
				switch s := val.(type) {
				case string:
					fn(k, s)
				case json.Number:
					fn(k, s.String())
				}
			}
			walkSecretFields(val, fn)
		}
	case []any:
		for _, val := range x {
			walkSecretFields(val, fn)
		}
	}
}

// redactJSON replaces, in place, the values of secret-named fields and the
// string values that equal a weak password.
func (r *redactor) redactJSON(v any) (any, bool) {
	changed := false
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if IsSecretField(k) {
				if val != Redacted {
					x[k] = Redacted
					changed = true
				}
				continue
			}
			if s, ok := val.(string); ok {
				if r.weak[s] {
					x[k] = Redacted
					changed = true
				}
				continue
			}
			if _, c := r.redactJSON(val); c {
				changed = true
			}
		}
	case []any:
		for i, val := range x {
			if s, ok := val.(string); ok {
				if r.weak[s] {
					x[i] = Redacted
					changed = true
				}
				continue
			}
			if _, c := r.redactJSON(val); c {
				changed = true
			}
		}
	}
	return v, changed
}

func copyHAR(h *HAR) *HAR {
	out := *h
	l := &out.Log
	l.Pages = append([]Page(nil), h.Log.Pages...)
	if h.Log.Entries != nil {
		l.Entries = make([]Entry, len(h.Log.Entries))
		for i, e := range h.Log.Entries {
			l.Entries[i] = copyEntry(e)
		}
	}
	if m := h.Log.Har2mcp; m != nil {
		mc := *m
		if m.Steps != nil {
			mc.Steps = make([]Step, len(m.Steps))
			for i, s := range m.Steps {
				s.Inputs = append([]TypedInput(nil), s.Inputs...)
				mc.Steps[i] = s
			}
		}
		if m.Login != nil {
			lc := *m.Login
			mc.Login = &lc
		}
		l.Har2mcp = &mc
	}
	return &out
}

func copyEntry(e Entry) Entry {
	e.Request.Cookies = copyCookies(e.Request.Cookies)
	e.Request.Headers = append([]NameValue(nil), e.Request.Headers...)
	e.Request.QueryString = append([]NameValue(nil), e.Request.QueryString...)
	if e.Request.PostData != nil {
		pd := *e.Request.PostData
		pd.Params = append([]Param(nil), pd.Params...)
		e.Request.PostData = &pd
	}
	e.Response.Cookies = copyCookies(e.Response.Cookies)
	e.Response.Headers = append([]NameValue(nil), e.Response.Headers...)
	if e.Trigger != nil {
		t := *e.Trigger
		e.Trigger = &t
	}
	e.WebSocketMessages = append([]WSMessage(nil), e.WebSocketMessages...)
	return e
}

func copyCookies(cs []Cookie) []Cookie {
	if cs == nil {
		return nil
	}
	out := make([]Cookie, len(cs))
	for i, c := range cs {
		if c.Expires != nil {
			t := *c.Expires
			c.Expires = &t
		}
		out[i] = c
	}
	return out
}
