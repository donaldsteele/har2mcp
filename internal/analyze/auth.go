package analyze

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
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
	secrets     []string // passwords sent as typed (plain HAR logins, Basic auth)
	tokenValues []string
	// pathTokens maps session-token values that requests carry in their URL
	// path to the name of the {placeholder} that stands for them.
	pathTokens map[string]string
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
// service that could be a login (API calls and form posts), in time order;
// onHost are all the requests to the service, pages included, in time order.
//
// In a recording, the login request is the one carrying the typed password
// (http mode: the generated server replays it), or failing that the one
// carrying the typed username or setting a cookie in the login step
// (browser mode: the page scrambled the password, so the server logs in
// through headless Chrome). Requests that carry an "Authorization: Basic"
// header and no login request mean HTTP Basic auth (basic mode). A plain
// HAR has no typed values, so a request with a password field and a strong
// sign of being a login (a login-like path, or a response that sets a
// cookie or returns a token) is taken and flagged for review.
func detectAuth(rec *recording, cands, onHost []*sample) *authResult {
	a := &authResult{login: map[*sample]bool{}, loginSteps: map[int]bool{}, carriers: map[string]bool{}, pathTokens: map[string]string{}}
	a.spec.Mode = "none"

	var (
		loginS    *sample
		capt      *capture
		mode      string
		username  string
		password  string
		heuristic bool
		rejected  *sample
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
	ha := detectHTTPAuth(onHost)
	if mode == "" && ha.basic {
		mode = "basic"
		a.secrets = append(a.secrets, ha.password)
	}
	if mode == "" && len(rec.captures) > 0 {
		capt, mode = &rec.captures[0], "browser"
	}
	if mode == "" {
		s, user, pass, rej := guessLogin(cands)
		if s != nil {
			loginS, mode, heuristic = s, "http", true
			username, password = user, pass
			a.secrets = append(a.secrets, pass)
		}
		rejected = rej
	}
	if mode == "" && ha.challenge {
		mode = "basic"
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

	tokens := detectTokens(rec, cands, onHost, a.login)
	for _, c := range tokens.carriers {
		a.carriers[c] = true
	}
	a.tokenValues = tokens.values
	a.pathTokens = tokens.pathTokens

	if mode == "" {
		if rec.plain {
			a.note("This is a plain HAR without har2mcp step labels and no login request was found in it. If the device needs a login, record a session with 'har2mcp record' so the login is captured.")
		}
		if rejected != nil {
			a.note("%s %s sends a password but does not look like a login (it changes a password or adds a user, or nothing marks it as a login: no login-like path, and no cookie or token in its response), so it was kept as a tool, not used as the login. If it is the login, describe it in auth.login and set auth.mode to http.",
				strings.ToUpper(rejected.e.Request.Method), rejected.u.EscapedPath())
		}
		if ha.digest {
			a.note("The device uses HTTP Digest authentication, which har2mcp does not support yet, so the generated server sends requests without a login and they will fail. Add the login in the generated server's custom.go, or use another way in to the device.")
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
	if mode == "basic" {
		a.spec.Session.Tokens = tokens.flows
		switch {
		case !ha.basic:
			a.note("The device asked for HTTP Basic authentication (WWW-Authenticate), but no request in the HAR carries the credentials (DevTools strips them from exported HARs), so har2mcp could not check them. Check auth.mode.")
		case len(rec.captures) > 0 && rec.captures[0].lc.Password != "" && rec.captures[0].lc.Password != ha.password:
			a.note("Requests carry HTTP Basic credentials that differ from the password typed in the login form. Check auth.mode.")
		}
		for _, n := range tokens.notes {
			a.note("%s", n)
		}
		return a
	}

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
		if l.Form.Submit == "" {
			a.note("The login form's submit button was not recorded (you pressed Enter, or clicked a control har2mcp could not tie to the form), so the generated server presses Enter in the password field to log in. If that does not log in, set auth.login.form.submit to the button's CSS selector.")
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

// httpAuth is what the requests say about HTTP authentication.
type httpAuth struct {
	basic              bool // a request carries Authorization: Basic
	username, password string
	challenge          bool // a response asked for Basic auth (WWW-Authenticate)
	digest             bool // Digest auth was asked for or used
}

// detectHTTPAuth looks for HTTP Basic and Digest authentication: the
// Authorization headers requests send and the WWW-Authenticate headers of
// 401 responses.
func detectHTTPAuth(samples []*sample) httpAuth {
	var ha httpAuth
	for _, s := range samples {
		for _, h := range s.e.Request.Headers {
			if !strings.EqualFold(h.Name, "authorization") {
				continue
			}
			scheme, cred, _ := strings.Cut(strings.TrimSpace(h.Value), " ")
			switch strings.ToLower(scheme) {
			case "basic":
				b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
				if err != nil {
					continue
				}
				if user, pass, ok := strings.Cut(string(b), ":"); ok && !ha.basic {
					ha.basic, ha.username, ha.password = true, user, pass
				}
			case "digest":
				ha.digest = true
			}
		}
		for _, h := range s.e.Response.Headers {
			if !strings.EqualFold(h.Name, "www-authenticate") {
				continue
			}
			for _, line := range strings.Split(h.Value, "\n") {
				scheme, _, _ := strings.Cut(strings.TrimSpace(line), " ")
				switch strings.ToLower(scheme) {
				case "basic":
					ha.challenge = true
				case "digest":
					ha.digest = true
				}
			}
		}
	}
	if ha.digest && !ha.basic {
		ha.challenge = false
	}
	return ha
}

// findPassword returns the request that sent the typed password: one with a
// field equal to it, else (for distinctive passwords) one with a field
// containing it. Requests in the login step win.
func findPassword(cands []*sample, c *capture) *sample {
	pw := c.lc.Password
	if s := findForCapture(cands, c, true, func(s *sample) bool { return carries(s, pw, false) }); s != nil {
		return s
	}
	if !har.Distinctive(pw) {
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

// changeStemsForLogin are words in a path or action that mark a request
// with a password field as changing a password or adding a user, not
// logging in.
var changeStemsForLogin = []string{"chang", "updat", "creat", "add", "new", "regist", "signup", "reset", "modif", "edit", "set", "save", "user", "account", "passw", "pwd"}

// neverLoginStems are the words among changeStemsForLogin that mark a
// password change or a sign-up even on a login-like path
// ("/cgi-bin/auth/changepw", "/api/auth/register"). The others ("user",
// "create", ...) also appear in real login paths ("/api/users/login",
// "/session/create"), so they count only on other paths.
var neverLoginStems = []string{"chang", "updat", "regist", "signup", "reset", "modif", "edit"}

// notLoginPasswordRE matches password field names of a password change:
// old_password, new_password, confirm_password and the like.
var notLoginPasswordRE = regexp.MustCompile(`(?i)old|new|confirm|repeat|verify|again|retype|current|2$`)

// guessLogin picks the login of a plain HAR: a request with one password
// field and a strong sign of being a login: a login-like path or action, or
// a response that sets a cookie or returns a token. A request with two
// password fields (old and new), a password field named like a password
// change, or a path that changes or adds something is not a login. When no
// request qualifies, rejected is the first that sent a password, for a
// review note.
func guessLogin(cands []*sample) (s *sample, username, password string, rejected *sample) {
	best, bestScore := (*sample)(nil), 0
	var bestUser, bestPass string
	for _, c := range cands {
		if strings.EqualFold(c.e.Request.Method, "GET") && len(c.req.fields) == 0 {
			continue
		}
		pass, user, passFields, changeField := "", "", 0, false
		for _, f := range c.req.fields {
			str, ok := f.value.(string)
			if !ok || str == "" {
				continue
			}
			switch {
			case isPasswordField(f.path):
				passFields++
				if notLoginPasswordRE.MatchString(lastSegment(f.path)) {
					changeField = true
				}
				if pass == "" {
					pass = str
				}
			case user == "" && isUsernameField(f.path):
				user = str
			}
		}
		if pass == "" {
			continue
		}
		_, vals := discriminators(c.req)
		where := c.u.Path + " " + strings.Join(vals, " ")
		loginLike := loginPathRE.MatchString(where)
		ws := words(where)
		changes := hasStem(ws, changeStemsForLogin, nil, nil)
		neverLogin := hasStem(ws, neverLoginStems, nil, nil)
		setsCookie := len(responseCookies(c.e)) > 0
		token := false
		if v, ok := responseJSON(c.e); ok {
			walkSecretFields(v, func(t string) {
				if looksTokenish(t) {
					token = true
				}
			})
		}
		if passFields > 1 || changeField || neverLogin || (!loginLike && (changes || !(setsCookie || token))) {
			if rejected == nil {
				rejected = c
			}
			continue
		}
		score := 1
		if loginLike {
			score += 2
		}
		if setsCookie {
			score++
		}
		if token {
			score++
		}
		if !strings.EqualFold(c.e.Request.Method, "GET") {
			score++
		}
		if score > bestScore {
			best, bestScore, bestUser, bestPass = c, score, user, pass
		}
	}
	if best == nil {
		return nil, "", "", rejected
	}
	return best, bestUser, bestPass, nil
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
			case password != "" && str == password && str == username:
				// The username and password are the same ("admin" and
				// "admin"): the field name tells them apart.
				v = "{{password}}"
				if isUsernameField(f.path) && !isPasswordField(f.path) {
					v = "{{username}}"
				}
			case password != "" && str == password:
				v = "{{password}}"
			case password != "" && har.Distinctive(password) && strings.Contains(str, password):
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
	r.Headers = replayableHeaders(s)
	return r
}

// replayableHeaders are the non-standard, non-secret headers of a request,
// which a replay of it sends as recorded.
func replayableHeaders(s *sample) map[string]string {
	var out map[string]string
	for _, h := range s.e.Request.Headers {
		if isStandardHeader(h.Name) || isSecretHeader(h.Name) {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		if _, dup := out[h.Name]; !dup {
			out[h.Name] = h.Value
		}
	}
	return out
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
