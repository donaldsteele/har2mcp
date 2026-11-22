package analyze

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// secretSet holds every secret value found in a recording: passwords,
// cookie values, tokens and the values of secret-named fields. Before the
// spec is returned, each of these is replaced with har.Redacted wherever it
// appears in a spec value.
//
// A password that is short or a common word ("admin", "1234") is weak: the
// same text is often an ordinary word in the device's paths and values
// ("/admin/login", "role: admin"), so it is only replaced where a whole
// value that could hold it equals it, never inside other text.
type secretSet struct {
	set  map[string]bool // replaced wherever they appear
	weak map[string]bool // replaced only as whole values
}

func newSecretSet() *secretSet { return &secretSet{set: map[string]bool{}, weak: map[string]bool{}} }

// add records v. always is for values known to be secret (passwords): they
// are replaced everywhere when distinctive (har.Distinctive), else only as
// whole values. Other values are kept when they are distinctive enough to
// scrub without mangling ordinary text (looksSecret).
func (s *secretSet) add(v string, always bool) {
	v = strings.TrimSpace(v)
	if v == "" || v == har.Redacted || isPlaceholder(v) {
		return
	}
	switch {
	case always && !har.Distinctive(v):
		s.weak[v] = true
		return
	case !always && !looksSecret(v):
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
func looksSecret(v string) bool { return har.LooksSecret(v) }

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

// value scrubs one whole value that could hold a password: a weak password
// it equals is replaced too.
func (s *secretSet) value(v string, list []string) string {
	if s.weak[strings.TrimSpace(v)] {
		return har.Redacted
	}
	return s.scrub(v, list)
}

// scrubAny returns v with secrets replaced in every string it contains.
// With whole set, strings that equal a weak password are replaced too.
func (s *secretSet) scrubAny(v any, list []string, whole bool) any {
	switch x := v.(type) {
	case string:
		if whole {
			return s.value(x, list)
		}
		return s.scrub(x, list)
	case map[string]any:
		for k, val := range x {
			x[k] = s.scrubAny(val, list, whole)
		}
		return x
	case []any:
		for i := range x {
			x[i] = s.scrubAny(x[i], list, whole)
		}
		return x
	default:
		return v
	}
}

// scrubFields scrubs fixed request values. A value under a secret-named
// field is a whole value that could hold a password; elsewhere a weak
// password is an ordinary word ("group: admin") and is kept.
func (s *secretSet) scrubFields(m map[string]any, list []string) {
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			s.scrubFields(sub, list)
			continue
		}
		m[k] = s.scrubAny(v, list, isSecretField(k))
	}
}

func (s *secretSet) scrubRequest(r *spec.Request, list []string) {
	s.scrubFields(r.Query, list)
	s.scrubFields(r.Body, list)
	for k, v := range r.Headers {
		r.Headers[k] = s.value(v, list)
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
	for i := range a.Session.Tokens {
		if r := a.Session.Tokens[i].Request; r != nil {
			s.scrubRequest(r, list)
		}
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
				in.Example = s.scrubAny(in.Example, list, true)
				if in.Example == har.Redacted {
					in.Example = nil
				}
			}
		}
		t.Response.Example = s.scrubAny(t.Response.Example, list, true)
		for j := range t.ReviewNotes {
			t.ReviewNotes[j] = s.scrub(t.ReviewNotes[j], list)
		}
		t.Source.Key = s.scrub(t.Source.Key, list)
		t.Source.Trigger = s.scrub(t.Source.Trigger, list)
		for j := range t.Source.Steps {
			t.Source.Steps[j] = s.scrub(t.Source.Steps[j], list)
		}
	}
	if s.weakLeft(sp) {
		a.Review = true
		a.ReviewNotes = append(a.ReviewNotes, "The password is short or a common word, and the same text also appears elsewhere in the spec (in a path or a value, for example), so har2mcp only removed it where a whole value matched. Check the spec by hand before you share it.")
	}
}

// weakLeft reports whether a weak password still appears anywhere in the
// spec, as part of other text.
func (s *secretSet) weakLeft(sp *spec.Spec) bool {
	if len(s.weak) == 0 {
		return false
	}
	b, err := json.Marshal(sp)
	if err != nil {
		return true
	}
	all := string(b)
	for w := range s.weak {
		enc, _ := json.Marshal(w)
		if strings.Contains(all, w) || strings.Contains(all, string(enc[1:len(enc)-1])) {
			return true
		}
	}
	return false
}

// isSecretHeader reports whether a header name suggests its value is a
// credential (har.IsSecretHeader).
func isSecretHeader(name string) bool { return har.IsSecretHeader(name) }

// isSecretField reports whether a body, form or query field name suggests a
// credential (har.IsSecretField). For dotted paths only the last part
// counts.
func isSecretField(name string) bool { return har.IsSecretField(name) }

// isPasswordField reports whether a field name is a password field.
func isPasswordField(name string) bool { return har.IsPasswordField(name) }

// sessionTokenWords are field-name parts that mark a session or CSRF token,
// as opposed to a credential the user chooses (a password or Wi-Fi key).
var sessionTokenWords = []string{"token", "csrf", "xsrf", "sessid", "session", "stok", "nonce"}

// isSessionTokenField reports whether a field name suggests a session or
// CSRF token: sid, stok, or a name with token, csrf or session in it.
func isSessionTokenField(name string) bool {
	n := strings.ToLower(lastSegment(name))
	if n == "sid" || n == "stok" || n == "auth" {
		return true
	}
	if isPasswordField(n) {
		return false
	}
	for _, w := range sessionTokenWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
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
		if har.IsSecretInput(tv.input) {
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
