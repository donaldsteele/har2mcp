package analyze

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// tokenSource is where a token value was first seen: a response (s, with
// fromLogin when it is the login response), or a cookie the browser sent
// (s is nil).
type tokenSource struct {
	ref       spec.TokenRef
	fromLogin bool
	s         *sample
}

type tokenResult struct {
	flows      []spec.TokenFlow
	carriers   []string
	values     []string
	notes      []string
	pathTokens map[string]string // token value -> path placeholder name
}

// responseHeadersSkipped are response headers that never carry a session
// token.
var responseHeadersSkipped = map[string]bool{
	"date": true, "content-type": true, "content-length": true, "content-encoding": true,
	"etag": true, "last-modified": true, "expires": true, "cache-control": true, "server": true,
	"set-cookie": true, "vary": true, "connection": true, "keep-alive": true,
	"transfer-encoding": true, "location": true, "x-powered-by": true, "age": true,
	"strict-transport-security": true, "content-security-policy": true, "accept-ranges": true,
	"x-content-type-options": true, "x-frame-options": true, "x-xss-protection": true,
	"referrer-policy": true, "permissions-policy": true, "content-disposition": true,
	"report-to": true, "nel": true, "alt-svc": true, "pragma": true,
}

// Limits on the text responses searched for tokens.
const (
	maxTextResponse  = 512 << 10 // bytes of one response
	maxTextResponses = 64        // most recent responses kept per HAR
)

// textResponse is a text, XML or HTML response kept to search for tokens.
type textResponse struct {
	s    *sample
	text string
}

// detectTokens finds values that a response handed out and later requests
// sent back: CSRF tokens in a header, bearer tokens, tokens in a query or
// body field, and session tokens in the URL path (OpenWrt's
// "/;stok=<token>/"). Each becomes a token flow, and the field that carries
// it is hidden from the tools. Tokens are looked for in JSON responses,
// response headers and cookies, and in text, XML and HTML responses (as a
// regular expression around the value, such as "<SID>([0-9a-f]+)</SID>").
//
// cands are the API calls and form posts, onHost every request to the
// service (pages included), both in time order. A token that comes from a
// response other than the login's keeps the request that returned it, so
// the generated server can make that request after logging in.
func detectTokens(rec *recording, cands, onHost []*sample, login map[*sample]bool) tokenResult {
	type carrier struct {
		loc, name string
		refs      map[spec.TokenRef]int
		srcs      map[spec.TokenRef]*sample
		first     spec.TokenRef
		prefix    string
	}
	res := tokenResult{pathTokens: map[string]string{}}
	byKey := map[string]*carrier{}
	var order []string
	secretHeaders := map[string]string{} // lower name -> name, headers that look secret
	record := func(loc, name string, src tokenSource, prefix, value string) {
		k := loc + "\x00" + name
		if loc == "header" {
			k = loc + "\x00" + strings.ToLower(name)
		}
		c := byKey[k]
		if c == nil {
			c = &carrier{loc: loc, name: name, refs: map[spec.TokenRef]int{}, srcs: map[spec.TokenRef]*sample{}, first: src.ref, prefix: prefix}
			byKey[k] = c
			order = append(order, k)
		}
		c.refs[src.ref]++
		if _, ok := c.srcs[src.ref]; !ok {
			c.srcs[src.ref] = src.s
		}
		res.values = append(res.values, value)
	}
	isCand := map[*sample]bool{}
	for _, s := range cands {
		isCand[s] = true
	}
	loginSeq := map[int]int{} // HAR -> seq of the login request
	for s := range login {
		loginSeq[s.har] = s.seq
	}

	for hi := range rec.hars {
		sources := map[string]tokenSource{}
		var texts []textResponse
		addSource := func(v string, src tokenSource) {
			for _, val := range []string{v, unescapeQuery(v)} {
				if looksTokenish(val) {
					if _, ok := sources[val]; !ok {
						sources[val] = src
					}
				}
			}
		}
		// find returns where a value a request sends came from: an earlier
		// response or cookie, or a text response that contains it.
		find := func(v string) (tokenSource, bool) {
			if src, ok := sources[v]; ok {
				return src, true
			}
			if !looksTokenish(v) {
				return tokenSource{}, false
			}
			for i := len(texts) - 1; i >= 0; i-- {
				t := texts[i]
				if !strings.Contains(t.text, v) {
					continue
				}
				if re := textTokenRegex(t.text, v); re != "" {
					src := tokenSource{ref: spec.TokenRef{ResponseText: re}, fromLogin: login[t.s], s: t.s}
					sources[v] = src
					return src, true
				}
			}
			return tokenSource{}, false
		}

		for _, s := range onHost {
			if s.har != hi {
				continue
			}
			for _, c := range requestCookies(s.e) {
				addSource(c.value, tokenSource{ref: spec.TokenRef{Cookie: c.name}})
			}
			if isCand[s] {
				for _, h := range s.e.Request.Headers {
					ln := strings.ToLower(h.Name)
					if ln == "cookie" || (isStandardHeader(ln) && ln != "authorization") {
						continue
					}
					v := strings.TrimSpace(h.Value)
					if v == "" || v == "null" || v == "undefined" {
						continue
					}
					if src, ok := find(v); ok {
						record("header", h.Name, src, "", v)
						continue
					}
					if i := strings.LastIndexByte(v, ' '); i > 0 {
						if src, ok := find(v[i+1:]); ok {
							record("header", h.Name, src, v[:i+1], v[i+1:])
							continue
						}
					}
					if isSecretHeader(ln) && !strings.HasPrefix(strings.ToLower(v), "basic ") && !strings.HasPrefix(strings.ToLower(v), "digest ") {
						secretHeaders[ln] = h.Name
					}
				}
				for _, f := range s.req.fields {
					str, ok := f.value.(string)
					if !ok || !looksTokenish(str) || login[s] {
						continue
					}
					if src, ok := sources[str]; ok && (isSecretField(f.path) || src.fromLogin) {
						record(f.loc, f.path, src, "", str)
						continue
					}
					if isSecretField(f.path) {
						if src, ok := find(str); ok {
							record(f.loc, f.path, src, "", str)
						}
					}
				}
				if !login[s] {
					for _, pt := range pathTokenCandidates(s.u) {
						src, ok := find(pt.value)
						if !ok || (pt.prefix == "" && !src.fromLogin) {
							continue
						}
						name := res.pathTokens[pt.value]
						if name == "" {
							name = pathTokenName(pt.prefix, src.ref)
							res.pathTokens[pt.value] = name
						}
						record("path", name, src, "", pt.value)
					}
				}
			}

			fromLogin := login[s]
			if v, ok := responseJSON(s.e); ok {
				walkLeaves("", v, func(path, str string) {
					addSource(str, tokenSource{ref: spec.TokenRef{ResponseJSON: path}, fromLogin: fromLogin, s: s})
				})
			} else if text, ok := responseText(s.e); ok {
				texts = append(texts, textResponse{s: s, text: text})
				if len(texts) > maxTextResponses {
					texts = texts[1:]
				}
			}
			for _, h := range s.e.Response.Headers {
				if !responseHeadersSkipped[strings.ToLower(h.Name)] && !strings.HasPrefix(strings.ToLower(h.Name), "access-control-") {
					addSource(strings.TrimSpace(h.Value), tokenSource{ref: spec.TokenRef{ResponseHeader: h.Name}, fromLogin: fromLogin, s: s})
				}
			}
			for _, c := range responseCookies(s.e) {
				addSource(c.value, tokenSource{ref: spec.TokenRef{Cookie: c.name}, fromLogin: fromLogin, s: s})
			}
		}
	}

	taken := map[string]bool{}
	for _, k := range order {
		c := byKey[k]
		// The most common source wins; ties go to the first one seen.
		ref := c.first
		refs := make([]spec.TokenRef, 0, len(c.refs))
		for r := range c.refs {
			refs = append(refs, r)
		}
		sort.Slice(refs, func(i, j int) bool { return fmt.Sprint(refs[i]) < fmt.Sprint(refs[j]) })
		for _, r := range refs {
			if c.refs[r] > c.refs[ref] {
				ref = r
			}
		}
		to := spec.TokenRef{}
		switch c.loc {
		case "header":
			to.Header = c.name
		case "query":
			to.Query = c.name
		case "path":
			to.Path = c.name
		default:
			to.Body = c.name
		}
		name := spec.UniqueName(spec.SanitizeName(c.name, 60), taken)
		flow := spec.TokenFlow{Name: name, From: ref, To: to, Prefix: c.prefix}
		src := c.srcs[ref]
		if src != nil && !login[src] && ref.Cookie == "" {
			r := sourceRequest(src, res.pathTokens)
			flow.Request = &r
			when := "after logging in"
			if len(login) == 0 {
				when = "before the first call"
			}
			before := ""
			if seq, ok := loginSeq[src.har]; ok && src.seq < seq {
				before = " It was recorded before the login, so it may need the login page's session instead."
			}
			res.notes = append(res.notes, fmt.Sprintf("Token %s comes from the response to %s %s, not from the login response, so the generated server sends that request %s and reads the token from it.%s Check auth.session.tokens.",
				name, r.Method, r.Path, when, before))
		}
		res.flows = append(res.flows, flow)
		res.carriers = append(res.carriers, k)
	}
	var unknown []string
	for ln, name := range secretHeaders {
		if byKey["header\x00"+ln] == nil {
			unknown = append(unknown, name)
		}
	}
	sort.Strings(unknown)
	for _, name := range unknown {
		res.notes = append(res.notes, fmt.Sprintf("Requests send the %s header, which looks like a credential, but its value was not found in any response, so it is left out of the spec. If the device needs it, add it in the generated server's custom.go.", name))
	}
	return res
}

// responseText returns a response body that is text: XML, HTML, plain text
// or a script, not too big to search.
func responseText(e *har.Entry) (string, bool) {
	if e.Response.Content.Truncated || isBinaryDownload(e) {
		return "", false
	}
	m := responseMIME(e)
	switch {
	case strings.HasPrefix(m, "image/"), strings.HasPrefix(m, "font/"), strings.HasPrefix(m, "audio/"),
		strings.HasPrefix(m, "video/"), m == "text/css":
		return "", false
	}
	b, err := e.Response.Content.Bytes()
	if err != nil || len(b) == 0 || len(b) > maxTextResponse || !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

// tokenValueRE is the character class of most tokens.
var tokenValueRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// textTokenRegex builds a regular expression that finds value in text: the
// shortest run of the text just before it (on the same line) that makes the
// first match of "<prefix>(<value's characters>)" be value itself. It
// returns "" when there is none.
func textTokenRegex(text, value string) string {
	i := strings.Index(text, value)
	if i < 0 {
		return ""
	}
	class := `[^"'<>\s&;,]+`
	if tokenValueRE.MatchString(value) {
		class = `[A-Za-z0-9_-]+`
	}
	for k := 3; k <= 48 && k <= i; k++ {
		prefix := text[i-k : i]
		if strings.ContainsAny(prefix, "\r\n") {
			break
		}
		if !utf8.ValidString(prefix) {
			continue
		}
		pattern := regexp.QuoteMeta(prefix) + "(" + class + ")"
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if m := re.FindStringSubmatch(text); m != nil && m[1] == value {
			return pattern
		}
	}
	return ""
}

// pathToken is a value in a URL path segment that may be a session token:
// a whole segment (prefix ""), or the part after "=" ("stok" for
// ";stok=<value>").
type pathToken struct{ prefix, value string }

func pathTokenCandidates(u *url.URL) []pathToken {
	var out []pathToken
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		seg = unescapeSeg(seg)
		if seg == "" {
			continue
		}
		if i := strings.LastIndexByte(seg, '='); i >= 0 {
			if v := seg[i+1:]; looksTokenish(v) {
				prefix := strings.TrimLeft(seg[:i], ";,&?")
				if j := strings.LastIndexAny(prefix, ";,&"); j >= 0 {
					prefix = prefix[j+1:]
				}
				if prefix == "" {
					prefix = "token"
				}
				out = append(out, pathToken{prefix: prefix, value: v})
			}
			continue
		}
		if looksTokenish(seg) {
			out = append(out, pathToken{value: seg})
		}
	}
	return out
}

// pathTokenName names the path placeholder of a session token: the name
// before "=" in the segment, else the name of the field it came from. It
// never looks like a path parameter ("id", "..._id").
func pathTokenName(prefix string, ref spec.TokenRef) string {
	base := prefix
	if base == "" {
		for _, v := range []string{lastSegment(ref.ResponseJSON), ref.ResponseHeader, ref.Cookie} {
			if v != "" {
				base = v
				break
			}
		}
	}
	name := spec.SanitizeName(base, 40)
	if name == "unnamed" {
		name = "session"
	}
	if prefix == "" && !strings.ContainsAny(name, "0123456789") {
		hasWord := false
		for _, w := range []string{"token", "sid", "sess", "stok", "key"} {
			hasWord = hasWord || strings.Contains(name, w)
		}
		if !hasWord {
			name += "_token"
		}
	}
	if name == "id" || strings.HasSuffix(name, "_id") {
		name += "_token"
	}
	return name
}

// rewritePathTokens replaces the session tokens in an escaped URL path with
// their {placeholder}s.
func rewritePathTokens(p string, tokens map[string]string) string {
	if len(tokens) == 0 {
		return p
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		u := unescapeSeg(seg)
		if name, ok := tokens[u]; ok {
			segs[i] = "{" + name + "}"
			continue
		}
		if j := strings.LastIndexByte(seg, '='); j >= 0 {
			if name, ok := tokens[unescapeSeg(seg[j+1:])]; ok {
				segs[i] = seg[:j+1] + "{" + name + "}"
			}
		}
	}
	return strings.Join(segs, "/")
}

// sourceRequest is the request that returned a token, to replay: its
// method, path, query and body as recorded, without secret fields (the
// server adds the session tokens itself).
func sourceRequest(s *sample, pathTokens map[string]string) spec.Request {
	path := rewritePathTokens(s.u.EscapedPath(), pathTokens)
	if path == "" {
		path = "/"
	}
	bodyType := s.req.bodyType
	if bodyType == "other" {
		bodyType = "none"
	}
	r := spec.Request{Method: strings.ToUpper(s.e.Request.Method), Path: path, BodyType: bodyType}
	for _, f := range s.req.fields {
		if isSecretField(f.path) {
			continue
		}
		if f.loc == "query" {
			if r.Query == nil {
				r.Query = map[string]any{}
			}
			r.Query[f.path] = f.value
			continue
		}
		if r.Body == nil {
			r.Body = map[string]any{}
		}
		if bodyType == "json" {
			setDotted(r.Body, f.path, f.value)
		} else {
			r.Body[f.path] = f.value
		}
	}
	r.Headers = replayableHeaders(s)
	return r
}

func unescapeQuery(v string) string {
	if u, err := url.QueryUnescape(v); err == nil {
		return u
	}
	return v
}

// walkLeaves calls fn with the dotted path and value of every string leaf.
func walkLeaves(prefix string, v any, fn func(path, value string)) {
	switch x := v.(type) {
	case string:
		if prefix != "" {
			fn(prefix, x)
		}
	case map[string]any:
		for _, k := range sortedKeys(x) {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			walkLeaves(p, x[k], fn)
		}
	case []any:
		for i, val := range x {
			p := strconv.Itoa(i)
			if prefix != "" {
				p = prefix + "." + p
			}
			walkLeaves(p, val, fn)
		}
	}
}
