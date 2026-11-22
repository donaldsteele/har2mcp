package analyze

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// authResult is what the auth stage found.
type authResult struct {
	spec       spec.Auth
	login      map[*sample]bool // the login request; its operation is not a tool
	loginSteps map[int]bool     // steps the user logged in during
	// carriers are the headers ("header\x00<lower name>"), query keys and
	// body fields that carry session tokens; the generated server fills them.
	carriers    map[string]bool
	secrets     []string // passwords sent as typed (plain HAR logins)
	tokenValues []string
}

func (a *authResult) isCarrier(loc, name string) bool {
	if loc == "header" {
		name = strings.ToLower(name)
	}
	return a.carriers[loc+"\x00"+name]
}

func (a *authResult) note(format string, args ...any) {
	a.spec.Review = true
	a.spec.ReviewNotes = append(a.spec.ReviewNotes, fmt.Sprintf(format, args...))
}

// isFormPost reports whether a request is a page form submission (a
// classic login), which the filter otherwise drops as an HTML document.
func isFormPost(s *sample) bool {
	if !strings.EqualFold(s.e.Request.Method, "POST") || s.e.Request.PostData == nil {
		return false
	}
	return strings.EqualFold(s.e.ResourceType, "document") || responseMIME(s.e) == "text/html"
}

// detectAuth finds the login and the session. cands are the requests to the
// service that could be a login (API calls and form posts), in time order.
//
// In a recording, the login request is the one carrying the typed password
// (http mode: the generated server replays it), or failing that the one
// carrying the typed username or setting a cookie in the login step
// (browser mode: the page scrambled the password, so the server logs in
// through headless Chrome). A plain HAR has no typed values, so a request
// with a password field on a login-like path is taken and flagged for
// review.
func detectAuth(rec *recording, cands []*sample) *authResult {
	a := &authResult{login: map[*sample]bool{}, loginSteps: map[int]bool{}, carriers: map[string]bool{}}
	a.spec.Mode = "none"

	var (
		loginS    *sample
		capt      *capture
		mode      string
		username  string
		password  string
		heuristic bool
	)
	for i := range rec.captures {
		c := &rec.captures[i]
		if c.lc.Password == "" {
			continue
		}
		if s := findPassword(cands, c); s != nil {
			loginS, capt, mode = s, c, "http"
			username, password = c.lc.Username, c.lc.Password
			break
		}
	}
	if loginS == nil {
		for i := range rec.captures {
			c := &rec.captures[i]
			s := findForCapture(cands, c, false, func(s *sample) bool {
				return c.lc.Username != "" && carries(s, c.lc.Username, false)
			})
			if s == nil {
				s = findForCapture(cands, c, false, func(s *sample) bool { return len(responseCookies(s.e)) > 0 })
			}
			if s != nil {
				loginS, capt, mode = s, c, "browser"
				username = c.lc.Username
				break
			}
		}
	}
	if mode == "" && len(rec.captures) > 0 {
		capt, mode = &rec.captures[0], "browser"
	}
	if mode == "" {
		if s, user, pass := guessLogin(cands); s != nil {
			loginS, mode, heuristic = s, "http", true
			username, password = user, pass
			a.secrets = append(a.secrets, pass)
		}
	}

	if loginS != nil {
		a.login[loginS] = true
		if loginS.step >= 0 {
			a.loginSteps[loginS.step] = true
		}
	}
	if capt != nil && capt.step >= 0 {
		a.loginSteps[capt.step] = true
	}

	tokens := detectTokens(rec, cands, a.login)
	for _, c := range tokens.carriers {
		a.carriers[c] = true
	}
	a.tokenValues = tokens.values

	if mode == "" {
		if rec.plain {
			a.note("This is a plain HAR without har2mcp step labels and no login request was found in it. If the device needs a login, record a session with 'har2mcp record' so the login is captured.")
		}
		if names := sessionCookiesSent(cands, nil); len(names) > 0 {
			a.note("Requests send the cookies %s, but no login was recorded, so the generated server cannot get them. Record the login with 'har2mcp record'.", strings.Join(names, ", "))
		}
		a.spec.Session.Tokens = tokens.flows
		if len(tokens.flows) > 0 {
			a.note("Session tokens were found but no login; check auth.session.")
		}
		for _, n := range tokens.notes {
			a.note("%s", n)
		}
		return a
	}

	a.spec.Mode = mode
	l := &spec.Login{}
	if capt != nil {
		page := capt.lc.PageURL
		if page == "" {
			if m := rec.hars[capt.har].Log.Har2mcp; m != nil {
				page = m.StartURL
			}
		}
		l.PageURL = relativeURL(page)
		if capt.lc.UsernameSelector != "" || capt.lc.PasswordSelector != "" {
			l.Form = &spec.LoginForm{Username: capt.lc.UsernameSelector, Password: capt.lc.PasswordSelector, Submit: capt.lc.SubmitSelector}
		}
	}
	if loginS != nil {
		l.Request = loginRequest(loginS, mode, username, password, a)
	} else {
		a.note("The login form was captured but no login request was found, so the generated server logs in through headless Chrome and keeps the cookies it gets. Check auth.session.cookies.")
	}
	if mode == "browser" {
		if l.Form == nil {
			l.Form = &spec.LoginForm{}
		}
		if l.Form.Username == "" || l.Form.Password == "" {
			if l.Form.Username == "" {
				l.Form.Username = "input[type=email], input[type=text], input:not([type])"
			}
			if l.Form.Password == "" {
				l.Form.Password = "input[type=password]"
			}
			a.note("The login form's field selectors were not all captured; auth.login.form uses generic ones. Check them against the login page.")
		}
		if l.PageURL == "" {
			l.PageURL = "/"
		}
	}
	a.spec.Login = l

	a.spec.Session.Cookies = sessionCookies(cands, loginS, capt)
	a.spec.Session.Tokens = tokens.flows
	a.spec.ReloginOn = []int{401, 403}
	a.spec.ReloginBodyContains = notLoggedInPhrase(cands)

	if heuristic {
		why := "This is a plain HAR without har2mcp step labels"
		if !rec.plain {
			why = "The recorder did not capture the login form"
		}
		a.note("%s, so the login request was guessed (%s %s) and har2mcp could not check that the password is sent as typed. Check auth.login, or record the login with 'har2mcp record'.",
			why, l.Request.Method, l.Request.Path)
	}
	switch {
	case len(a.spec.Session.Cookies) > 0:
	case rec.plain:
		a.note("No session cookie was seen (DevTools strips cookies from exported HARs). The generated server keeps whatever cookies the device sets; name the session cookie in auth.session.cookies if you know it.")
	case len(a.spec.Session.Tokens) == 0:
		a.note("No session cookie or token was found after the login; check auth.session.")
	}
	for _, n := range tokens.notes {
		a.note("%s", n)
	}
	return a
}

// findPassword returns the request that sent the typed password: one with a
// field equal to it, else (for passwords of at least 6 characters) one with
// a field containing it. Requests in the login step win.
func findPassword(cands []*sample, c *capture) *sample {
	pw := c.lc.Password
	if s := findForCapture(cands, c, true, func(s *sample) bool { return carries(s, pw, false) }); s != nil {
		return s
	}
	if len(pw) < 6 {
		return nil
	}
	return findForCapture(cands, c, true, func(s *sample) bool { return carries(s, pw, true) })
}

// carries reports whether a request has a field equal to v, or containing
// it when substr is set.
func carries(s *sample, v string, substr bool) bool {
	for _, f := range s.req.fields {
		str, ok := f.value.(string)
		if !ok {
			continue
		}
		if str == v || (substr && strings.Contains(str, v)) {
			return true
		}
	}
	return false
}

// findForCapture returns the first request of the capture's HAR matching ok
// in the capture's step, or, failing that, anywhere in the HAR. GET requests
// count only when getOK is set.
func findForCapture(cands []*sample, c *capture, getOK bool, ok func(*sample) bool) *sample {
	var fallback *sample
	for _, s := range cands {
		if s.har != c.har || (!getOK && strings.EqualFold(s.e.Request.Method, "GET")) || !ok(s) {
			continue
		}
		if c.step >= 0 && s.step == c.step {
			return s
		}
		if fallback == nil {
			fallback = s
		}
	}
	return fallback
}

var loginPathRE = regexp.MustCompile(`(?i)log_?in|log_?on|sign_?in|sign-in|auth|session`)

// guessLogin picks the most login-like request of a plain HAR: one with a
// password field, preferably on a login-like path or action, setting
// cookies or returning a token.
func guessLogin(cands []*sample) (s *sample, username, password string) {
	best, bestScore := (*sample)(nil), 0
	var bestUser, bestPass string
	for _, c := range cands {
		if strings.EqualFold(c.e.Request.Method, "GET") && len(c.req.fields) == 0 {
			continue
		}
		pass, user := "", ""
		for _, f := range c.req.fields {
			str, ok := f.value.(string)
			if !ok || str == "" {
				continue
			}
			switch {
			case pass == "" && isPasswordField(f.path):
				pass = str
			case user == "" && isUsernameField(f.path):
				user = str
			}
		}
		if pass == "" {
			continue
		}
		score := 3
		_, vals := discriminators(c.req)
		if loginPathRE.MatchString(c.u.Path) || loginPathRE.MatchString(strings.Join(vals, " ")) {
			score += 2
		}
		if len(responseCookies(c.e)) > 0 {
			score++
		}
		if v, ok := responseJSON(c.e); ok {
			found := false
			walkSecretFields(v, func(t string) {
				if looksTokenish(t) {
					found = true
				}
			})
			if found {
				score++
			}
		}
		if !strings.EqualFold(c.e.Request.Method, "GET") {
			score++
		}
		if score > bestScore {
			best, bestScore, bestUser, bestPass = c, score, user, pass
		}
	}
	if bestScore < 4 {
		return nil, "", ""
	}
	return best, bestUser, bestPass
}

func isUsernameField(name string) bool {
	n := strings.ToLower(lastSegment(name))
	switch n {
	case "user", "username", "user_name", "login", "loginname", "login_name", "account", "email", "uname", "usr", "userid", "user_id", "name":
		return true
	}
	return strings.Contains(n, "user") || strings.Contains(n, "login") || strings.Contains(n, "email")
}

// loginRequest builds auth.login.request. In http mode the typed username
// and password become {{username}} and {{password}}; in browser mode only
// the method and path are kept, for reference.
func loginRequest(s *sample, mode, username, password string, a *authResult) spec.Request {
	path := s.u.EscapedPath()
	if path == "" {
		path = "/"
	}
	bodyType := s.req.bodyType
	if bodyType == "other" {
		bodyType = "none"
	}
	r := spec.Request{Method: strings.ToUpper(s.e.Request.Method), Path: path, BodyType: bodyType}
	if mode != "http" {
		return r
	}
	if s.req.bodyType == "other" {
		a.note("The login request body is %s, which har2mcp cannot replay; switch auth.mode to browser or fill in auth.login.request by hand.", s.req.mime)
	}
	for _, f := range s.req.fields {
		v := f.value
		if str, ok := v.(string); ok {
			switch {
			case password != "" && str == password:
				v = "{{password}}"
			case password != "" && len(password) >= 4 && strings.Contains(str, password):
				v = strings.ReplaceAll(str, password, "{{password}}")
			case username != "" && str == username:
				v = "{{username}}"
			case isSecretField(f.path) || a.isCarrier(f.loc, f.path):
				v = har.Redacted
				a.note("The login request sends %s field %q, which looks like a token from the page; har2mcp cannot fill it. Check auth.login.request.", f.loc, f.path)
			}
		}
		if f.loc == "query" {
			if r.Query == nil {
				r.Query = map[string]any{}
			}
			r.Query[f.path] = v
			continue
		}
		if r.Body == nil {
			r.Body = map[string]any{}
		}
		if bodyType == "json" {
			setDotted(r.Body, f.path, v)
		} else {
			r.Body[f.path] = v
		}
	}
	for _, h := range s.e.Request.Headers {
		if isStandardHeader(h.Name) || isSecretHeader(h.Name) {
			continue
		}
		if r.Headers == nil {
			r.Headers = map[string]string{}
		}
		if _, dup := r.Headers[h.Name]; !dup {
			r.Headers[h.Name] = h.Value
		}
	}
	return r
}

var sessionCookieRE = regexp.MustCompile(`(?i)sess|sid|auth|token|login|jwt|user|remember`)

// sessionCookies names the cookies that carry the session: those the login
// response set and later requests sent back, else those it set, else
// session-like cookies later requests sent.
func sessionCookies(cands []*sample, loginS *sample, capt *capture) []string {
	if loginS != nil {
		set := responseCookies(loginS.e)
		sent := map[string]bool{}
		for _, s := range cands {
			if s.har == loginS.har && s.seq > loginS.seq {
				for _, c := range requestCookies(s.e) {
					sent[c.name] = true
				}
			}
		}
		var both, all []string
		for _, c := range set {
			if strings.EqualFold(c.value, "deleted") || c.value == "" {
				continue
			}
			all = append(all, c.name)
			if sent[c.name] {
				both = append(both, c.name)
			}
		}
		if len(both) > 0 {
			return sortedUnique(both)
		}
		if len(all) > 0 {
			return sortedUnique(all)
		}
		return sessionCookiesSent(cands, loginS)
	}
	if capt != nil {
		var after []*sample
		for _, s := range cands {
			if s.har == capt.har && (capt.step < 0 || s.step < 0 || s.step >= capt.step) {
				after = append(after, s)
			}
		}
		return sessionCookiesSent(after, nil)
	}
	return nil
}

// sessionCookiesSent lists session-like cookies that requests (after
// loginS, when given) sent.
func sessionCookiesSent(cands []*sample, loginS *sample) []string {
	var out []string
	for _, s := range cands {
		if loginS != nil && (s.har != loginS.har || s.seq <= loginS.seq) {
			continue
		}
		for _, c := range requestCookies(s.e) {
			if sessionCookieRE.MatchString(c.name) {
				out = append(out, c.name)
			}
		}
	}
	return sortedUnique(out)
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// looksTokenish reports whether a value could be a session or CSRF token:
// at least 8 characters, no spaces, and a digit or at least 16 characters.
func looksTokenish(v string) bool {
	if len(v) < 8 || strings.IndexFunc(v, unicode.IsSpace) >= 0 {
		return false
	}
	return len(v) >= 16 || strings.IndexFunc(v, unicode.IsDigit) >= 0
}

type tokenSource struct {
	ref       spec.TokenRef
	fromLogin bool
}

type tokenResult struct {
	flows    []spec.TokenFlow
	carriers []string
	values   []string
	notes    []string
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

// detectTokens finds values that a response handed out and later requests
// sent back: CSRF tokens in a header, bearer tokens, tokens in a query or
// body field. Each becomes a token flow, and the field that carries it is
// hidden from the tools.
func detectTokens(rec *recording, cands []*sample, login map[*sample]bool) tokenResult {
	type carrier struct {
		loc, name string
		refs      map[spec.TokenRef]int
		first     spec.TokenRef
		prefix    string
	}
	var res tokenResult
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
			c = &carrier{loc: loc, name: name, refs: map[spec.TokenRef]int{}, first: src.ref, prefix: prefix}
			byKey[k] = c
			order = append(order, k)
		}
		c.refs[src.ref]++
		res.values = append(res.values, value)
	}

	for hi := range rec.hars {
		sources := map[string]tokenSource{}
		addSource := func(v string, src tokenSource) {
			for _, val := range []string{v, unescapeQuery(v)} {
				if looksTokenish(val) {
					if _, ok := sources[val]; !ok {
						sources[val] = src
					}
				}
			}
		}
		for _, s := range cands {
			if s.har != hi {
				continue
			}
			for _, c := range requestCookies(s.e) {
				addSource(c.value, tokenSource{ref: spec.TokenRef{Cookie: c.name}})
			}
			for _, h := range s.e.Request.Headers {
				ln := strings.ToLower(h.Name)
				if ln == "cookie" || (isStandardHeader(ln) && ln != "authorization") {
					continue
				}
				v := strings.TrimSpace(h.Value)
				if v == "" || v == "null" || v == "undefined" {
					continue
				}
				if src, ok := sources[v]; ok {
					record("header", h.Name, src, "", v)
					continue
				}
				if i := strings.LastIndexByte(v, ' '); i > 0 {
					if src, ok := sources[v[i+1:]]; ok {
						record("header", h.Name, src, v[:i+1], v[i+1:])
						continue
					}
				}
				if isSecretHeader(ln) {
					secretHeaders[ln] = h.Name
				}
			}
			for _, f := range s.req.fields {
				str, ok := f.value.(string)
				if !ok || !looksTokenish(str) {
					continue
				}
				if src, ok := sources[str]; ok && !login[s] && (isSecretField(f.path) || src.fromLogin) {
					record(f.loc, f.path, src, "", str)
				}
			}

			fromLogin := login[s]
			if v, ok := responseJSON(s.e); ok {
				walkLeaves("", v, func(path, str string) {
					addSource(str, tokenSource{ref: spec.TokenRef{ResponseJSON: path}, fromLogin: fromLogin})
				})
			}
			for _, h := range s.e.Response.Headers {
				if !responseHeadersSkipped[strings.ToLower(h.Name)] && !strings.HasPrefix(strings.ToLower(h.Name), "access-control-") {
					addSource(strings.TrimSpace(h.Value), tokenSource{ref: spec.TokenRef{ResponseHeader: h.Name}, fromLogin: fromLogin})
				}
			}
			for _, c := range responseCookies(s.e) {
				addSource(c.value, tokenSource{ref: spec.TokenRef{Cookie: c.name}, fromLogin: fromLogin})
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
		default:
			to.Body = c.name
		}
		name := spec.UniqueName(spec.SanitizeName(c.name, 60), taken)
		res.flows = append(res.flows, spec.TokenFlow{Name: name, From: ref, To: to})
		res.carriers = append(res.carriers, k)
		if c.prefix != "" {
			res.notes = append(res.notes, fmt.Sprintf("The %s header sends the token after %q; check that the generated server adds that prefix.", c.name, strings.TrimSpace(c.prefix)))
		}
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

// notLoggedInPhrases are response texts that mean the session has expired.
var notLoggedInPhrases = []string{
	"not logged in", "not login", "not logged", "login required", "please log in", "please login",
	"session expired", "session has expired", "session timeout", "session timed out",
	"invalid session", "no session", "need login", "login timeout", "relogin",
	"not authenticated", "unauthenticated", "authentication required", "unauthorized",
}

// notLoggedInPhrase returns the first "not logged in" phrase seen in a
// short or failed response, with the response's own capitalization.
func notLoggedInPhrase(cands []*sample) string {
	for _, pass := range []int{0, 1} {
		for _, s := range cands {
			st := s.e.Response.Status
			if (pass == 0 && st != 401 && st != 403) || s.e.Response.Content.Truncated {
				continue
			}
			b, err := s.e.Response.Content.Bytes()
			if err != nil || len(b) == 0 || (st < 400 && len(b) > 1024) || len(b) > 8192 {
				continue
			}
			text := string(b)
			lower := strings.ToLower(text)
			for _, p := range notLoggedInPhrases {
				i := strings.Index(lower, p)
				switch {
				case i < 0:
				case len(lower) == len(text):
					return text[i : i+len(p)]
				default:
					return p
				}
			}
		}
	}
	return ""
}
