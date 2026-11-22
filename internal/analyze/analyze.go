// Package analyze turns recorded HAR files into a har2mcp spec.
//
// The stages run in the order the design lists them:
//
//  1. filter: keep API calls to the service's hosts; drop static files,
//     HTML pages and other hosts (filter.go)
//  2. auth: find the login request, decide http or browser mode, and work
//     out the session cookies and tokens (auth.go)
//  3. group: key each call on method, normalized path and discriminator,
//     splitting RPC endpoints by their action field (group.go)
//  4. params: decide which values are inputs and which stay fixed
//     (params.go)
//  5. schema: infer a JSON schema and keep one redacted example (schema.go)
//  6. classify: read, change or destructive (classify.go)
//  7. files: uploads, downloads and chunked uploads (files.go)
//  8. naming: tool names and descriptions from the step labels (naming.go)
//
// The spec never contains recorded secrets: values are checked against every
// password, cookie and token found in the recording and replaced with
// har.Redacted.
package analyze

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// Options controls Analyze.
type Options struct {
	// Name is the service name. "" derives it from the host (DeriveName).
	Name string
	// Hosts are the hosts whose requests are analyzed, as "host" (any port)
	// or "host:port". nil uses the host of the recording's start URL, or,
	// for a plain HAR, the host most XHR and fetch calls went to.
	Hosts []string
}

var serviceNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// Analyze builds a spec from one or more HAR files: har2mcp recordings or
// plain HARs such as Chrome DevTools exports. The spec is valid and holds no
// recorded passwords, cookies or tokens. Tool.Generated and
// Spec.AuthGenerated are filled so that spec.Merge can tell hand edits apart.
func Analyze(hars []*har.HAR, opts Options) (*spec.Spec, error) {
	if len(hars) == 0 {
		return nil, errors.New("no HAR files to analyze")
	}
	for i, h := range hars {
		if h == nil {
			return nil, fmt.Errorf("HAR %d is empty", i+1)
		}
	}
	if opts.Name != "" && !serviceNameRE.MatchString(opts.Name) {
		return nil, fmt.Errorf("service name %q is not valid: use lower case letters, digits and _, start with a letter, at most 32 characters (for example %q)",
			opts.Name, spec.SanitizeName(opts.Name, 32))
	}

	rec := newRecording(hars)
	hosts := pickHosts(rec, opts.Hosts)
	if len(hosts) == 0 {
		return nil, errors.New("the HAR files contain no HTTP requests")
	}

	r := analyzeHosts(rec, hosts)
	if len(r.ops) == 0 && len(opts.Hosts) == 0 {
		// The start page may have sent the browser to another host by
		// script (tplinkwifi.net -> 192.168.0.1); try the host the browser
		// went to that most API calls went to.
		if busy := navigatedHosts(rec); len(busy) > 0 && !hostMatchesAny(busy, hosts) {
			if r2 := analyzeHosts(rec, union(hosts, busy)); len(r2.ops) > 0 {
				hosts, r = union(hosts, busy), r2
			}
		}
	}
	if len(r.ops) == 0 {
		return nil, fmt.Errorf("found no API calls to %s: %d requests in total, %d to that host, all of them static files, pages or the login. If the device's API is on another host, pass it with --host",
			strings.Join(hosts, ", "), len(rec.samples), len(r.onHost))
	}
	au, ops, calls := r.au, r.ops, r.calls

	drafts := make([]*draft, 0, len(ops))
	for _, op := range ops {
		drafts = append(drafts, buildTool(rec, op, au))
	}
	nameTools(rec, drafts, au)

	s := &spec.Spec{
		Har2mcp: spec.FormatVersion,
		Service: spec.Service{Hosts: hosts, BaseURL: baseURL(rec, hosts, calls, au)},
		Auth:    au.spec,
	}
	s.Service.Name = opts.Name
	if s.Service.Name == "" {
		host := hosts[0]
		if u, err := url.Parse(s.Service.BaseURL); err == nil && u.Host != "" {
			host = u.Host
		}
		s.Service.Name = DeriveName(host)
	}
	for _, d := range drafts {
		s.Tools = append(s.Tools, d.tool)
	}

	sec := rec.secrets
	for _, v := range au.secrets {
		sec.add(v, true)
	}
	for _, v := range au.tokenValues {
		sec.add(v, false)
	}
	sec.scrubSpec(s)

	for i := range s.Tools {
		s.Tools[i].Generated = spec.GeneratedHashes(&s.Tools[i])
	}
	s.AuthGenerated = spec.FieldHash(s.Auth)
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("analysis produced an invalid spec (this is a har2mcp bug; please report it with 'har2mcp inspect' output): %w", err)
	}
	return s, nil
}

// DeriveName turns a host into a service name: the first DNS label,
// sanitized ("tos-nas.home.arpa" -> "tos_nas"). A leading "www." is
// skipped. IP addresses, localhost and empty hosts give "device".
func DeriveName(host string) string {
	h := strings.TrimSpace(strings.ToLower(host))
	if strings.Contains(h, "://") {
		if u, err := url.Parse(h); err == nil {
			h = u.Host
		}
	}
	h = hostOnly(h)
	if h == "" || h == "localhost" || isIP(h) {
		return "device"
	}
	labels := strings.Split(h, ".")
	first := labels[0]
	if first == "www" && len(labels) > 2 {
		first = labels[1]
	}
	name := spec.SanitizeName(first, 32)
	if name == "unnamed" {
		return "device"
	}
	return name
}

// sample is one HAR entry with what the stages need to know about it.
type sample struct {
	har  int        // index of the HAR file
	seq  int        // position across all HAR files, in time order
	e    *har.Entry // the entry as recorded
	red  *har.Entry // the same entry with secrets redacted (for examples)
	u    *url.URL
	time time.Time
	step int // step instance (index into recording.steps), -1 outside any step
	req  parsedRequest
}

func (s *sample) triggered() bool {
	t := s.e.Trigger
	return t != nil && (t.Text != "" || t.AriaLabel != "" || t.Selector != "" || t.Role != "")
}

// stepInfo is one labeled step. A label used twice gives two steps.
type stepInfo struct {
	har    int
	label  string
	start  time.Time
	inputs []har.TypedInput
}

// typedValue is a value the user typed, with the step it was typed in.
type typedValue struct {
	har   int
	step  int
	input har.TypedInput
}

type recording struct {
	hars     []*har.HAR
	samples  []*sample
	steps    []stepInfo
	typed    []typedValue
	captures []capture // login forms, one per HAR at most
	plain    bool      // no HAR carries har2mcp data
	// respStrings maps string values seen in JSON responses to the first
	// sample that returned them, per HAR.
	respStrings []map[string]int
	secrets     *secretSet
}

// capture is a login form the recorder saw submitted (or one pieced together
// from typed inputs).
type capture struct {
	har  int
	step int
	lc   har.LoginCapture
}

func newRecording(hars []*har.HAR) *recording {
	rec := &recording{hars: hars, plain: true, secrets: newSecretSet()}
	seq := 0
	for hi, h := range hars {
		red := har.Redact(h)
		meta := h.Log.Har2mcp
		if meta != nil {
			rec.plain = false
		}

		// Steps: those in the metadata, then any label only entries name.
		firstStep := len(rec.steps)
		if meta != nil {
			for _, st := range meta.Steps {
				rec.steps = append(rec.steps, stepInfo{har: hi, label: st.Name, start: st.Start, inputs: st.Inputs})
			}
		}

		order := make([]int, len(h.Log.Entries))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool {
			return h.Log.Entries[order[a]].StartedDateTime.Before(h.Log.Entries[order[b]].StartedDateTime)
		})
		for _, i := range order {
			e := &h.Log.Entries[i]
			u, err := url.Parse(e.Request.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				continue
			}
			s := &sample{har: hi, seq: seq, e: e, red: &red.Log.Entries[i], u: u, time: e.StartedDateTime, step: -1}
			seq++
			if e.Step != "" {
				s.step = rec.stepFor(hi, firstStep, meta, e.Step, e.StartedDateTime)
			}
			s.req = parseRequest(e, u)
			rec.samples = append(rec.samples, s)
		}

		if meta != nil {
			for i, st := range meta.Steps {
				for _, in := range st.Inputs {
					if strings.TrimSpace(in.Value) != "" {
						rec.typed = append(rec.typed, typedValue{har: hi, step: firstStep + i, input: in})
					}
				}
			}
			if c, ok := rec.captureFor(hi, firstStep, meta); ok {
				rec.captures = append(rec.captures, c)
			}
		}
	}

	rec.respStrings = make([]map[string]int, len(hars))
	for i := range rec.respStrings {
		rec.respStrings[i] = map[string]int{}
	}
	for _, s := range rec.samples {
		if v, ok := responseJSON(s.e); ok {
			walkStrings(v, func(str string) {
				if len(str) >= 2 {
					if _, seen := rec.respStrings[s.har][str]; !seen {
						rec.respStrings[s.har][str] = s.seq
					}
				}
			})
		}
	}
	rec.collectSecrets()
	return rec
}

// stepFor maps an entry's step label to a step instance. With metadata the
// entry's time picks between steps that share a label; otherwise each label
// is one step.
func (rec *recording) stepFor(hi, firstStep int, meta *har.Meta, label string, t time.Time) int {
	if meta != nil {
		best := -1
		for i, st := range meta.Steps {
			if st.Name != label {
				continue
			}
			if !t.Before(st.Start) && (st.End.IsZero() || !t.After(st.End)) {
				best = i // the last matching step wins
			}
		}
		if best < 0 {
			for i, st := range meta.Steps {
				if st.Name == label && (best < 0 || !t.Before(st.Start)) {
					best = i
				}
			}
		}
		if best >= 0 {
			return firstStep + best
		}
	}
	for i := firstStep; i < len(rec.steps); i++ {
		if rec.steps[i].har == hi && rec.steps[i].label == label && (meta == nil || i >= firstStep+len(meta.Steps)) {
			return i
		}
	}
	rec.steps = append(rec.steps, stepInfo{har: hi, label: label, start: t})
	return len(rec.steps) - 1
}

// captureFor returns the login form of a recording: the recorder's capture,
// or one pieced together from a typed password input.
func (rec *recording) captureFor(hi, firstStep int, meta *har.Meta) (capture, bool) {
	if lc := meta.Login; lc != nil && (lc.Password != "" || lc.PasswordSelector != "") {
		c := capture{har: hi, step: -1, lc: *lc}
		// The first step the password was typed in, if the recorder logged
		// it (a later "change password" step may type it again).
	steps:
		for i, st := range meta.Steps {
			for _, in := range st.Inputs {
				if strings.EqualFold(in.Type, "password") && in.Value == lc.Password {
					c.step = firstStep + i
					break steps
				}
			}
		}
		return c, true
	}
	for i, st := range meta.Steps {
		for j, in := range st.Inputs {
			if !strings.EqualFold(in.Type, "password") || in.Value == "" {
				continue
			}
			c := capture{har: hi, step: firstStep + i, lc: har.LoginCapture{
				PageURL:          meta.StartURL,
				Password:         in.Value,
				PasswordSelector: in.Selector,
			}}
			for k := j - 1; k >= 0; k-- {
				if t := strings.ToLower(st.Inputs[k].Type); t == "" || t == "text" || t == "email" || t == "tel" {
					c.lc.Username = st.Inputs[k].Value
					c.lc.UsernameSelector = st.Inputs[k].Selector
					break
				}
			}
			return c, true
		}
	}
	return capture{}, false
}

// hostsResult is the analysis of the requests to one set of hosts.
type hostsResult struct {
	onHost []*sample // every request to the hosts, in time order
	calls  []*sample // the API calls among them
	au     *authResult
	ops    []*operation // the operations that become tools
}

// analyzeHosts runs the filter, auth and group stages on the requests to
// hosts.
func analyzeHosts(rec *recording, hosts []string) hostsResult {
	var r hostsResult
	// calls are the API requests that can become tools; authCands also
	// include page form posts, which can be a classic login.
	var authCands []*sample
	for _, s := range rec.samples {
		if !hostMatches(s.u, hosts) {
			continue
		}
		r.onHost = append(r.onHost, s)
		switch {
		case !isStatic(s):
			r.calls = append(r.calls, s)
			authCands = append(authCands, s)
		case isFormPost(s):
			authCands = append(authCands, s)
		}
	}

	r.au = detectAuth(rec, authCands, r.onHost)

	// The login's operation is not a tool, and every step it happens in
	// (one per recording) is a login step.
	for _, op := range group(rec, r.calls, r.au.pathTokens) {
		if !op.containsAny(r.au.login) {
			r.ops = append(r.ops, op)
			continue
		}
		for _, s := range op.samples {
			if s.step >= 0 {
				r.au.loginSteps[s.step] = true
			}
		}
	}
	return r
}

// baseURL is the origin (scheme://host[:port]) the device's API ran on: the
// login request's, else the one most API calls went to, else the start
// URL's. The start URL can differ: a device typed as http://nas:8181 may
// redirect to https://nas:5443, where the API really is.
func baseURL(rec *recording, hosts []string, calls []*sample, au *authResult) string {
	var login *sample
	for s := range au.login {
		if login == nil || s.seq < login.seq {
			login = s
		}
	}
	if login != nil {
		return login.u.Scheme + "://" + login.u.Host
	}
	count := map[string]int{}
	var order []string
	for _, s := range calls {
		o := s.u.Scheme + "://" + s.u.Host
		if count[o] == 0 {
			order = append(order, o)
		}
		count[o]++
	}
	best := ""
	for _, o := range order {
		if best == "" || count[o] > count[best] {
			best = o
		}
	}
	if best != "" {
		return best
	}
	for _, h := range rec.hars {
		if m := h.Log.Har2mcp; m != nil && m.StartURL != "" {
			if u, err := url.Parse(m.StartURL); err == nil && u.Host != "" && hostMatches(u, hosts) {
				return u.Scheme + "://" + u.Host
			}
		}
	}
	return ""
}

func union(a, b []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// relativeURL returns the path, query and fragment of a URL, so it can be
// resolved against the service URL the generated server is given.
func relativeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return "/"
	}
	out := u.EscapedPath()
	if out == "" {
		out = "/"
	}
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.EscapedFragment()
	}
	return out
}
