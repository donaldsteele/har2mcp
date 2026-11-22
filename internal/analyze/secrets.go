package analyze

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// secretSet holds every secret value found in a recording: passwords,
// cookie values, tokens and the values of secret-named fields. Before the
// spec is returned, each of these is replaced with har.Redacted wherever it
// appears in a spec value.
type secretSet struct {
	set map[string]bool
}

func newSecretSet() *secretSet { return &secretSet{set: map[string]bool{}} }

// add records v. always is for values known to be secret (passwords);
// other values are only kept when they are distinctive enough to scrub
// without mangling ordinary text.
func (s *secretSet) add(v string, always bool) {
	v = strings.TrimSpace(v)
	if v == "" || v == har.Redacted || isPlaceholder(v) {
		return
	}
	if !always && !looksSecret(v) {
		return
	}
	s.set[v] = true
	s.set[url.QueryEscape(v)] = true
	s.set[url.PathEscape(v)] = true
	if b, err := json.Marshal(v); err == nil {
		s.set[string(b[1:len(b)-1])] = true
	}
}

// looksSecret reports whether a value found in a secret place is distinctive
// enough to scrub everywhere: at least 6 characters with a digit, or at
// least 12 characters.
func looksSecret(v string) bool {
	if len(v) < 6 {
		return false
	}
	return len(v) >= 12 || strings.IndexFunc(v, unicode.IsDigit) >= 0
}

func isPlaceholder(v string) bool { return v == "{{password}}" || v == "{{username}}" }

func (s *secretSet) list() []string {
	out := make([]string, 0, len(s.set))
	for v := range s.set {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

func (s *secretSet) scrub(v string, list []string) string {
	if v == "" || isPlaceholder(v) {
		return v
	}
	for _, sec := range list {
		if strings.Contains(v, sec) {
			v = strings.ReplaceAll(v, sec, har.Redacted)
		}
	}
	return v
}

// scrubAny returns v with secrets replaced in every string it contains.
func (s *secretSet) scrubAny(v any, list []string) any {
	switch x := v.(type) {
	case string:
		return s.scrub(x, list)
	case map[string]any:
		for k, val := range x {
			x[k] = s.scrubAny(val, list)
		}
		return x
	case []any:
		for i := range x {
			x[i] = s.scrubAny(x[i], list)
		}
		return x
	default:
		return v
	}
}

func (s *secretSet) scrubRequest(r *spec.Request, list []string) {
	for k, v := range r.Query {
		r.Query[k] = s.scrubAny(v, list)
	}
	for k, v := range r.Body {
		r.Body[k] = s.scrubAny(v, list)
	}
	for k, v := range r.Headers {
		r.Headers[k] = s.scrub(v, list)
	}
	r.Path = s.scrub(r.Path, list)
}

// scrubSpec replaces every known secret in the spec's values.
func (s *secretSet) scrubSpec(sp *spec.Spec) {
	list := s.list()
	if u, err := url.Parse(sp.Service.BaseURL); err == nil && u.User != nil {
		u.User = nil
		sp.Service.BaseURL = u.String()
	}
	sp.Service.BaseURL = s.scrub(sp.Service.BaseURL, list)
	a := &sp.Auth
	if a.Login != nil {
		a.Login.PageURL = s.scrub(a.Login.PageURL, list)
		s.scrubRequest(&a.Login.Request, list)
	}
	for i := range a.ReviewNotes {
		a.ReviewNotes[i] = s.scrub(a.ReviewNotes[i], list)
	}
	for i := range sp.Tools {
		t := &sp.Tools[i]
		t.Description = s.scrub(t.Description, list)
		s.scrubRequest(&t.Request, list)
		for j := range t.Inputs {
			in := &t.Inputs[j]
			in.Description = s.scrub(in.Description, list)
			if in.Example != nil {
				in.Example = s.scrubAny(in.Example, list)
				if in.Example == har.Redacted {
					in.Example = nil
				}
			}
		}
		t.Response.Example = s.scrubAny(t.Response.Example, list)
		for j := range t.ReviewNotes {
			t.ReviewNotes[j] = s.scrub(t.ReviewNotes[j], list)
		}
		t.Source.Trigger = s.scrub(t.Source.Trigger, list)
		for j := range t.Source.Steps {
			t.Source.Steps[j] = s.scrub(t.Source.Steps[j], list)
		}
	}
}

var (
	secretHeaderWords = []string{"token", "csrf", "xsrf", "session", "auth", "secret", "password", "api-key", "apikey", "api_key", "cookie"}
	secretFieldExact  = map[string]bool{"password": true, "passwd": true, "pwd": true, "pass": true, "token": true, "csrf": true, "sid": true, "secret": true, "pin": true, "psk": true, "otp": true}
	secretFieldWords  = []string{"password", "passwd", "passphrase", "token", "csrf", "xsrf", "secret", "sessid", "sessionid", "session_id", "apikey", "api_key", "access_key", "private_key", "psk", "wpa_key", "wpakey", "wifi_key", "wifikey"}
)

// isSecretHeader reports whether a header name suggests its value is a
// credential.
func isSecretHeader(name string) bool {
	n := strings.ToLower(name)
	for _, w := range secretHeaderWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// isSecretField reports whether a body, form or query field name suggests a
// credential. For dotted paths only the last part counts.
func isSecretField(name string) bool {
	n := strings.ToLower(lastSegment(name))
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

// isPasswordField reports whether a field name is a password field.
func isPasswordField(name string) bool {
	n := strings.ToLower(lastSegment(name))
	switch n {
	case "password", "passwd", "pwd", "pass", "passphrase", "pass_word", "pw":
		return true
	}
	return strings.Contains(n, "password") || strings.Contains(n, "passwd")
}

// collectSecrets gathers passwords, cookie values, secret header values and
// secret-named fields from every request and response.
func (rec *recording) collectSecrets() {
	s := rec.secrets
	for _, c := range rec.captures {
		s.add(c.lc.Password, true)
	}
	for _, h := range rec.hars {
		if m := h.Log.Har2mcp; m != nil && m.Login != nil {
			s.add(m.Login.Password, true)
		}
	}
	for _, tv := range rec.typed {
		if strings.EqualFold(tv.input.Type, "password") {
			s.add(tv.input.Value, true)
		}
	}
	for _, smp := range rec.samples {
		e := smp.e
		for _, c := range e.Request.Cookies {
			s.add(c.Value, false)
		}
		for _, c := range e.Response.Cookies {
			s.add(c.Value, false)
		}
		for _, hs := range [][]har.NameValue{e.Request.Headers, e.Response.Headers} {
			for _, h := range hs {
				switch strings.ToLower(h.Name) {
				case "cookie":
					for _, ck := range parseCookieHeader(h.Value) {
						s.add(ck.value, false)
					}
				case "set-cookie":
					for _, ck := range parseSetCookie(h.Value) {
						s.add(ck.value, false)
					}
				default:
					if isSecretHeader(h.Name) {
						v := strings.TrimSpace(h.Value)
						s.add(v, false)
						if i := strings.LastIndexByte(v, ' '); i >= 0 {
							s.add(v[i+1:], false)
						}
					}
				}
			}
		}
		for _, f := range smp.req.fields {
			if isSecretField(f.path) {
				if str, ok := f.value.(string); ok {
					s.add(str, isPasswordField(f.path))
				}
			}
		}
		if v, ok := responseJSON(e); ok {
			walkSecretFields(v, func(str string) { s.add(str, false) })
		}
	}
}

// walkSecretFields calls fn with every string or number under a
// secret-named key.
func walkSecretFields(v any, fn func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if isSecretField(k) {
				switch sv := val.(type) {
				case string:
					fn(sv)
				case json.Number:
					fn(sv.String())
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

type cookiePair struct{ name, value string }

// parseCookieHeader splits a Cookie request header into its pairs.
func parseCookieHeader(v string) []cookiePair {
	var out []cookiePair
	for _, part := range strings.Split(v, ";") {
		name, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && name != "" {
			out = append(out, cookiePair{name: strings.TrimSpace(name), value: strings.Trim(strings.TrimSpace(val), `"`)})
		}
	}
	return out
}

// parseSetCookie reads one or more Set-Cookie values (Chrome joins several
// with newlines).
func parseSetCookie(v string) []cookiePair {
	var out []cookiePair
	for _, line := range strings.Split(v, "\n") {
		first, _, _ := strings.Cut(line, ";")
		name, val, ok := strings.Cut(strings.TrimSpace(first), "=")
		if ok && name != "" {
			out = append(out, cookiePair{name: strings.TrimSpace(name), value: strings.Trim(strings.TrimSpace(val), `"`)})
		}
	}
	return out
}

// requestCookies lists the cookies a request sent, from its cookie list and
// its Cookie header.
func requestCookies(e *har.Entry) []cookiePair {
	var out []cookiePair
	seen := map[string]bool{}
	for _, c := range e.Request.Cookies {
		if !seen[c.Name] {
			seen[c.Name] = true
			out = append(out, cookiePair{name: c.Name, value: c.Value})
		}
	}
	for _, h := range e.Request.Headers {
		if strings.EqualFold(h.Name, "cookie") {
			for _, c := range parseCookieHeader(h.Value) {
				if !seen[c.name] {
					seen[c.name] = true
					out = append(out, c)
				}
			}
		}
	}
	return out
}

// responseCookies lists the cookies a response set.
func responseCookies(e *har.Entry) []cookiePair {
	var out []cookiePair
	seen := map[string]bool{}
	for _, c := range e.Response.Cookies {
		if !seen[c.Name] {
			seen[c.Name] = true
			out = append(out, cookiePair{name: c.Name, value: c.Value})
		}
	}
	for _, h := range e.Response.Headers {
		if strings.EqualFold(h.Name, "set-cookie") {
			for _, c := range parseSetCookie(h.Value) {
				if !seen[c.name] {
					seen[c.name] = true
					out = append(out, c)
				}
			}
		}
	}
	return out
}
