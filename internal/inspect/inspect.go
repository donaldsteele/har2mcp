// Package inspect prints summaries of HAR files and specs that are safe to
// read or share: what was recorded, the detected auth mode, the operations,
// the review flags and the file tools. They never include passwords,
// cookies, tokens, typed values, request bodies or response examples.
package inspect

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/donaldsteele/har2mcp/internal/analyze"
	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// errWriter remembers the first write error so the printing code can stay
// straight-line.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	e.err = err
	return n, err
}

func plural(n int, one string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %ss", n, one)
}

// HAR prints what a HAR file holds (kind, request count, hosts, steps,
// whether a login form was captured), then analyzes it with opts and prints
// the resulting spec's summary. When analysis fails, the HAR summary is
// still printed and the analysis error is returned (not printed).
func HAR(w io.Writer, h *har.HAR, opts analyze.Options) error {
	ew := &errWriter{w: w}
	meta := h.Log.Har2mcp

	fmt.Fprintln(ew, "HAR file")
	if meta != nil {
		fmt.Fprintf(ew, "  kind:     har2mcp recording (recorder %s)\n", orDash(meta.Version))
	} else {
		creator := strings.TrimSpace(h.Log.Creator.Name + " " + h.Log.Creator.Version)
		if creator == "" {
			creator = "an unknown program"
		}
		fmt.Fprintf(ew, "  kind:     plain HAR from %s: no step labels or typed values, so results need more review\n", creator)
	}

	ws := 0
	hostCount := map[string]int{}
	stepCount := map[string]int{}
	for _, e := range h.Log.Entries {
		ws += len(e.WebSocketMessages)
		if u, err := url.Parse(e.Request.URL); err == nil && u.Host != "" {
			hostCount[strings.ToLower(u.Host)]++
		}
		if e.Step != "" {
			stepCount[e.Step]++
		}
	}
	line := plural(len(h.Log.Entries), "request")
	if ws > 0 {
		line += fmt.Sprintf(", %s (recorded, not used)", plural(ws, "WebSocket message"))
	}
	fmt.Fprintf(ew, "  contents: %s\n", line)

	hosts := make([]string, 0, len(hostCount))
	for host := range hostCount {
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hostCount[hosts[i]] != hostCount[hosts[j]] {
			return hostCount[hosts[i]] > hostCount[hosts[j]]
		}
		return hosts[i] < hosts[j]
	})
	var hl []string
	for i, host := range hosts {
		if i == 8 {
			hl = append(hl, fmt.Sprintf("and %d more", len(hosts)-8))
			break
		}
		hl = append(hl, fmt.Sprintf("%s (%d)", host, hostCount[host]))
	}
	fmt.Fprintf(ew, "  hosts:    %s\n", orDash(strings.Join(hl, ", ")))

	if meta != nil {
		if len(meta.Steps) == 0 {
			fmt.Fprintln(ew, "  steps:    none labeled")
		} else {
			fmt.Fprintln(ew, "  steps:")
			done := map[string]bool{}
			for i, st := range meta.Steps {
				name := st.Name
				if strings.TrimSpace(name) == "" {
					name = "(no name)"
				}
				count := ""
				if !done[st.Name] {
					// Entries carry the label only, so a label used twice
					// counts its requests once, on its first step.
					done[st.Name] = true
					count = " (" + plural(stepCount[st.Name], "request") + ")"
				}
				fmt.Fprintf(ew, "    %d. %s%s\n", i+1, name, count)
			}
		}
		if lc := meta.Login; lc != nil {
			fmt.Fprintf(ew, "  login:    form captured (%s)\n", selectors(lc.UsernameSelector, lc.PasswordSelector, lc.SubmitSelector))
		} else {
			fmt.Fprintln(ew, "  login:    no login form captured")
		}
	}
	fmt.Fprintln(ew)

	s, err := analyze.Analyze([]*har.HAR{h}, opts)
	if err != nil {
		if ew.err != nil {
			return ew.err
		}
		return err
	}
	if err := Spec(ew, s); err != nil {
		return err
	}
	return ew.err
}

// Spec prints a spec's service, auth, tools (one line each:
// <kind> <name> <METHOD> <path>), file tools and review flags. It prints no
// values from the spec's requests, so a secret pasted into a spec by hand
// does not show up.
func Spec(w io.Writer, s *spec.Spec) error {
	ew := &errWriter{w: w}
	p := s.EnvPrefix()
	hasFiles := false
	for _, t := range s.Tools {
		if t.File != nil {
			hasFiles = true
		}
	}

	fmt.Fprintf(ew, "Service: %s\n", orDash(s.Service.Name))
	env := []string{p + "_URL"}
	if s.Auth.Mode != "none" && s.Auth.Mode != "" {
		env = append(env, p+"_USER", p+"_PASSWORD")
	}
	env = append(env, p+"_INSECURE")
	if hasFiles {
		env = append(env, p+"_FILES_DIR")
	}
	fmt.Fprintf(ew, "  env:      %s\n", strings.Join(env, ", "))
	if s.Service.BaseURL != "" {
		fmt.Fprintf(ew, "  recorded: %s\n", s.Service.BaseURL)
	}
	fmt.Fprintln(ew)

	printAuth(ew, &s.Auth)
	fmt.Fprintln(ew)

	enabled := 0
	kinds := map[string]int{}
	for _, t := range s.Tools {
		if t.Enabled {
			enabled++
		}
		kinds[t.Kind]++
	}
	var kl []string
	for _, k := range []string{"read", "change", "destructive"} {
		if kinds[k] > 0 {
			kl = append(kl, fmt.Sprintf("%d %s", kinds[k], k))
		}
	}
	summary := fmt.Sprintf("%d enabled", enabled)
	if len(kl) > 0 {
		summary += "; " + strings.Join(kl, ", ")
	}
	fmt.Fprintf(ew, "Tools: %d (%s)\n", len(s.Tools), summary)
	tw := newTable(ew, 2)
	for _, t := range s.Tools {
		var extra []string
		if d := discriminator(t.Request); d != "" {
			extra = append(extra, d)
		}
		if !t.Enabled {
			extra = append(extra, "(disabled)")
		}
		if t.Review {
			extra = append(extra, "[review]")
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s %s\t%s\n", orDash(t.Kind), t.Name, t.Request.Method, t.Request.Path, strings.Join(extra, " "))
	}
	tw.Flush()
	fmt.Fprintln(ew)

	fmt.Fprintln(ew, "Files:")
	if !hasFiles {
		fmt.Fprintln(ew, "  no upload or download tools")
	} else {
		tw = newTable(ew, 2)
		for _, t := range s.Tools {
			f := t.File
			if f == nil {
				continue
			}
			desc := f.Direction
			if f.Part != "" {
				desc += fmt.Sprintf(", multipart part %q", f.Part)
			}
			if c := f.Chunked; c != nil {
				var parts []string
				for _, kv := range [][2]string{{"offset", c.OffsetField}, {"index", c.IndexField}, {"total", c.TotalField}} {
					if kv[1] != "" {
						parts = append(parts, fmt.Sprintf("%s %q", kv[0], kv[1]))
					}
				}
				desc += fmt.Sprintf(", chunked by %d bytes (%s)", c.ChunkSize, strings.Join(parts, ", "))
			}
			fmt.Fprintf(tw, "  %s\t%s\n", t.Name, desc)
		}
		tw.Flush()
	}
	fmt.Fprintln(ew)

	var review []string
	if s.Auth.Review {
		if len(s.Auth.ReviewNotes) == 0 {
			review = append(review, "auth: flagged for review")
		}
		for _, n := range s.Auth.ReviewNotes {
			review = append(review, "auth: "+n)
		}
	}
	for _, t := range s.Tools {
		if !t.Review {
			continue
		}
		if len(t.ReviewNotes) == 0 {
			review = append(review, t.Name+": flagged for review")
		}
		for _, n := range t.ReviewNotes {
			review = append(review, t.Name+": "+n)
		}
	}
	if len(review) == 0 {
		fmt.Fprintln(ew, "Review: nothing flagged.")
	} else {
		fmt.Fprintf(ew, "Review: %d to check\n", len(review))
		for _, r := range review {
			fmt.Fprintf(ew, "  - %s\n", r)
		}
	}
	return ew.err
}

func printAuth(w io.Writer, a *spec.Auth) {
	fmt.Fprintf(w, "Auth: %s\n", orDash(a.Mode))
	switch a.Mode {
	case "http":
		fmt.Fprintln(w, "  the server replays the login request with the username and password")
	case "browser":
		fmt.Fprintln(w, "  the page scrambles the password, so the server logs in through headless Chrome")
	}
	tw := newTable(w, 1)
	if l := a.Login; l != nil {
		if l.Request.Method != "" || l.Request.Path != "" {
			fmt.Fprintf(tw, "  login:\t%s %s\n", l.Request.Method, l.Request.Path)
		}
		if l.PageURL != "" {
			fmt.Fprintf(tw, "  login page:\t%s\n", l.PageURL)
		}
		if f := l.Form; f != nil {
			fmt.Fprintf(tw, "  form:\t%s\n", selectors(f.Username, f.Password, f.Submit))
		}
	}
	if len(a.Session.Cookies) > 0 {
		fmt.Fprintf(tw, "  cookies:\t%s\n", strings.Join(a.Session.Cookies, ", "))
	}
	for _, tf := range a.Session.Tokens {
		fmt.Fprintf(tw, "  token:\t%s: %s -> %s\n", tf.Name, tokenRef(tf.From), tokenRef(tf.To))
	}
	if len(a.ReloginOn) > 0 || a.ReloginBodyContains != "" {
		var codes []string
		for _, c := range a.ReloginOn {
			codes = append(codes, fmt.Sprint(c))
		}
		r := ""
		if len(codes) > 0 {
			r = "on " + strings.Join(codes, ", ")
		}
		if a.ReloginBodyContains != "" {
			if r != "" {
				r += ", or "
			}
			r += fmt.Sprintf("when a response contains %q", a.ReloginBodyContains)
		}
		fmt.Fprintf(tw, "  log in again:\t%s\n", r)
	}
	tw.Flush()
}

func tokenRef(r spec.TokenRef) string {
	for _, kv := range [][2]string{
		{"response_json", r.ResponseJSON}, {"response_header", r.ResponseHeader}, {"cookie", r.Cookie},
		{"header", r.Header}, {"query", r.Query}, {"body", r.Body},
	} {
		if kv[1] != "" {
			return kv[0] + " " + kv[1]
		}
	}
	return "?"
}

// discriminator shows a tool's action field and value ("act=getdisklist").
func discriminator(r spec.Request) string {
	if r.Discriminator == "" {
		return ""
	}
	var parts []string
	for _, f := range strings.Split(r.Discriminator, ",") {
		v, ok := r.Body[f]
		if !ok {
			v, ok = r.Query[f]
		}
		if ok {
			parts = append(parts, fmt.Sprintf("%s=%v", f, v))
		} else {
			parts = append(parts, f+"=?")
		}
	}
	return strings.Join(parts, " ")
}

func selectors(user, pass, submit string) string {
	var parts []string
	for _, s := range []string{user, pass, submit} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return orDash(strings.Join(parts, ", "))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// table aligns tab-separated columns like text/tabwriter and drops the
// padding tabwriter leaves at the end of lines whose last cell is empty.
type table struct {
	out io.Writer
	buf strings.Builder
	tw  *tabwriter.Writer
}

func newTable(w io.Writer, padding int) *table {
	t := &table{out: w}
	t.tw = tabwriter.NewWriter(&t.buf, 0, 0, padding, ' ', 0)
	return t
}

func (t *table) Write(p []byte) (int, error) { return t.tw.Write(p) }

// Flush writes the aligned table.
func (t *table) Flush() error {
	if err := t.tw.Flush(); err != nil {
		return err
	}
	var b strings.Builder
	for _, line := range strings.SplitAfter(t.buf.String(), "\n") {
		if strings.HasSuffix(line, "\n") {
			b.WriteString(strings.TrimRight(line, " \n"))
			b.WriteByte('\n')
		} else {
			b.WriteString(strings.TrimRight(line, " "))
		}
	}
	t.buf.Reset()
	_, err := io.WriteString(t.out, b.String())
	return err
}
