package har

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

// Redact returns a deep copy of h with secrets replaced by Redacted. h is not
// modified. These are removed:
//
//   - the Cookie, Set-Cookie and Authorization headers, and every header whose
//     name contains token, csrf, session or auth (case-insensitive)
//   - every cookie value
//   - the captured login password and every typed input of type "password"
//   - those passwords wherever they appear in URLs, query strings, bodies
//     and headers, raw or URL- or JSON-encoded
//   - JSON body fields (request, response and WebSocket, any depth, any case)
//     named password, passwd, pwd, pass, token or csrf, or whose name contains
//     password, passwd, token, csrf, secret or a session-id or API-key word;
//     form and query fields with those names are redacted too
//   - the values found in all of the above (session ids, CSRF tokens, bearer
//     tokens) wherever else they appear, when they look like secrets: at least
//     6 characters with a digit, or at least 12 characters
func Redact(h *HAR) *HAR {
	if h == nil {
		return nil
	}
	out := copyHAR(h)
	r := &redactor{}
	r.collect(out)
	r.apply(out)
	return out
}

var (
	secretHeaderWords = []string{"token", "csrf", "session", "auth", "secret", "password", "api-key", "apikey"}
	secretFieldExact  = map[string]bool{"password": true, "passwd": true, "pwd": true, "pass": true, "token": true, "csrf": true}
	secretFieldWords  = []string{"password", "passwd", "token", "csrf", "secret", "sessid", "sessionid", "session_id", "apikey", "api_key"}
)

func isSecretHeader(name string) bool {
	n := strings.ToLower(name)
	if n == "cookie" || n == "set-cookie" {
		return true
	}
	for _, w := range secretHeaderWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

func isSecretField(name string) bool {
	n := strings.ToLower(name)
	if secretFieldExact[n] {
		return true
	}
	for _, w := range secretFieldWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// looksSecret reports whether a value found in a secret place is distinctive
// enough to scrub everywhere else without mangling ordinary text.
func looksSecret(v string) bool {
	if v == Redacted || len(v) < 6 {
		return false
	}
	if len(v) >= 12 {
		return true
	}
	return strings.IndexFunc(v, unicode.IsDigit) >= 0
}

type redactor struct {
	secrets map[string]bool
	list    []string // longest first
}

func (r *redactor) addAlways(v string) {
	if v == "" || v == Redacted {
		return
	}
	if r.secrets == nil {
		r.secrets = map[string]bool{}
	}
	r.secrets[v] = true
	r.secrets[url.QueryEscape(v)] = true
	r.secrets[url.PathEscape(v)] = true
	if b, err := json.Marshal(v); err == nil {
		r.secrets[string(b[1:len(b)-1])] = true
	}
}

func (r *redactor) addFound(v string) {
	v = strings.TrimSpace(v)
	if looksSecret(v) {
		r.addAlways(v)
	}
}

// collect gathers every secret value in h before anything is changed.
func (r *redactor) collect(h *HAR) {
	if m := h.Log.Har2mcp; m != nil {
		if m.Login != nil {
			r.addAlways(m.Login.Password)
		}
		for _, s := range m.Steps {
			for _, in := range s.Inputs {
				if strings.EqualFold(in.Type, "password") {
					r.addAlways(in.Value)
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
			if isSecretField(q.Name) {
				r.addFound(q.Value)
			}
		}
		if pd := e.Request.PostData; pd != nil {
			for _, p := range pd.Params {
				if isSecretField(p.Name) {
					r.addFound(p.Value)
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

func (r *redactor) collectHeaders(hs []NameValue) {
	for _, h := range hs {
		if !isSecretHeader(h.Name) {
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
		walkSecretFields(v, func(s string) { r.addFound(s) })
		return
	}
	if isForm(mime) {
		for _, pair := range strings.Split(string(b), "&") {
			k, v, _ := strings.Cut(pair, "=")
			if name, err := url.QueryUnescape(k); err == nil && isSecretField(name) {
				if val, err := url.QueryUnescape(v); err == nil {
					r.addFound(val)
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

func (r *redactor) apply(h *HAR) {
	if m := h.Log.Har2mcp; m != nil {
		m.StartURL = r.scrub(m.StartURL)
		if m.Login != nil {
			if m.Login.Password != "" {
				m.Login.Password = Redacted
			}
			m.Login.PageURL = r.scrub(m.Login.PageURL)
		}
		for i := range m.Steps {
			for j := range m.Steps[i].Inputs {
				in := &m.Steps[i].Inputs[j]
				if strings.EqualFold(in.Type, "password") {
					in.Value = Redacted
				} else {
					in.Value = r.scrub(in.Value)
				}
			}
		}
	}
	for i := range h.Log.Entries {
		e := &h.Log.Entries[i]
		req, resp := &e.Request, &e.Response
		req.URL = r.scrub(req.URL)
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
			if isSecretField(q.Name) {
				q.Value = Redacted
			} else {
				q.Value = r.scrub(q.Value)
			}
		}
		if pd := req.PostData; pd != nil {
			for j := range pd.Params {
				p := &pd.Params[j]
				if isSecretField(p.Name) {
					p.Value = Redacted
				} else {
					p.Value = r.scrub(p.Value)
				}
			}
			pd.Text = string(r.redactBody([]byte(pd.Text), pd.MimeType))
		}
		resp.RedirectURL = r.scrub(resp.RedirectURL)
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
		if isSecretHeader(hs[i].Name) {
			hs[i].Value = Redacted
		} else {
			hs[i].Value = r.scrub(hs[i].Value)
		}
	}
}

// redactBody redacts secret-named fields of a JSON or form body, then scrubs
// known secret values from what is left. Other bodies are only scrubbed.
func (r *redactor) redactBody(b []byte, mime string) []byte {
	if v, ok := parseJSON(b); ok {
		if nv, changed := redactJSON(v); changed {
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
			k, _, hasValue := strings.Cut(pair, "=")
			if name, err := url.QueryUnescape(k); err == nil && hasValue && isSecretField(name) {
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

// walkSecretFields calls fn with every string or number found under a secret
// field name.
func walkSecretFields(v any, fn func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if isSecretField(k) {
				switch s := val.(type) {
				case string:
					fn(s)
				case json.Number:
					fn(s.String())
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

// redactJSON replaces the values of secret-named fields in place.
func redactJSON(v any) (any, bool) {
	changed := false
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if isSecretField(k) {
				if val != Redacted {
					x[k] = Redacted
					changed = true
				}
				continue
			}
			if _, c := redactJSON(val); c {
				changed = true
			}
		}
	case []any:
		for _, val := range x {
			if _, c := redactJSON(val); c {
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
