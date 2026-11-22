package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/donaldsteele/har2mcp/internal/analyze"
	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

var analyzeNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// runAnalyze implements 'har2mcp analyze'.
func runAnalyze(args []string) error {
	return analyzeTo(os.Stdout, args)
}

func analyzeTo(stdout io.Writer, args []string) error {
	flags := newFlagSet("analyze")
	out := flags.String("o", "", "spec file to write, or to update if it exists (default <name>.spec.yaml)")
	name := flags.String("name", "", "service name: the generated server's name and environment variable prefix (default: from the host)")
	var hosts multiFlag
	flags.Var(&hosts, "host", "analyze requests to this host, as host or host:port; repeat for several (default: the recorded site)")
	files, err := parseInterspersed(flags, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return usageErrorf("analyze needs at least one HAR file")
	}
	if *name != "" && !analyzeNameRE.MatchString(*name) {
		return usageErrorf("--name %q is not a valid service name: use lower case letters, digits and _, starting with a letter, at most 32 characters (for example %q)",
			*name, spec.SanitizeName(*name, 32))
	}

	hars := make([]*har.HAR, 0, len(files))
	for _, f := range files {
		h, err := har.Load(f)
		if err != nil {
			return err
		}
		hars = append(hars, h)
	}
	fresh, err := analyze.Analyze(hars, analyze.Options{Name: *name, Hosts: hosts})
	if err != nil {
		return fmt.Errorf("%s: %w", strings.Join(files, ", "), err)
	}

	path := *out
	if path == "" {
		path = fresh.Service.Name + ".spec.yaml"
	}
	result := fresh
	var existing *spec.Spec
	switch _, statErr := os.Stat(path); {
	case statErr == nil:
		existing, err = spec.Load(path)
		if err != nil {
			return fmt.Errorf("%s already exists but could not be read, so it was not changed. Fix it, or write a new spec with -o:\n%w", path, err)
		}
		result = spec.Merge(existing, fresh)
		if *name != "" {
			result.Service.Name = *name
		}
		if err := result.Validate(); err != nil {
			return fmt.Errorf("merging this recording into %s gives an invalid spec, so the file was not changed. Fix these fields in %s, or move it away to start over:\n%w", path, path, err)
		}
	case !errors.Is(statErr, fs.ErrNotExist):
		return statErr
	}
	if err := spec.Save(path, result); err != nil {
		return err
	}
	printAnalyzeSummary(stdout, path, result, existing, startOrigin(hars))
	return nil
}

// printAnalyzeSummary reports what was written and what to do next. start
// is the origin of the recorded start URL, or "".
func printAnalyzeSummary(w io.Writer, path string, s *spec.Spec, existing *spec.Spec, start string) {
	kinds := map[string]int{}
	for _, t := range s.Tools {
		kinds[t.Kind]++
	}
	var kl []string
	for _, k := range []string{"read", "change", "destructive"} {
		if kinds[k] > 0 {
			kl = append(kl, fmt.Sprintf("%d %s", kinds[k], k))
		}
	}
	tools := fmt.Sprintf("%d tools", len(s.Tools))
	if len(s.Tools) == 1 {
		tools = "1 tool"
	}
	if len(kl) > 0 {
		tools += " (" + strings.Join(kl, ", ") + ")"
	}
	fmt.Fprintf(w, "Wrote %s: %s, auth mode %s.\n", path, tools, s.Auth.Mode)
	if start != "" && s.Service.BaseURL != "" && !strings.EqualFold(start, s.Service.BaseURL) {
		fmt.Fprintf(w, "Note: the device's API answered at %s, not at the address you recorded (%s), so the spec and the generated server use %s.\n",
			s.Service.BaseURL, start, s.Service.BaseURL)
	}

	if existing != nil {
		old := map[string]bool{}
		for _, t := range existing.Tools {
			old[t.Source.Key] = true
		}
		added := 0
		for _, t := range s.Tools {
			if !old[t.Source.Key] {
				added++
			}
		}
		fmt.Fprintf(w, "Merged into the existing spec: %d new, %d already there. Your edits to names, descriptions, enabled, kind, inputs and auth were kept.\n",
			added, len(s.Tools)-added)
	}

	var review []string
	if s.Auth.Review {
		review = append(review, "auth")
	}
	for _, t := range s.Tools {
		if t.Review {
			review = append(review, t.Name)
		}
	}
	if len(review) > 0 {
		fmt.Fprintf(w, "Check before generating (review: true in the spec): %s.\n", strings.Join(review, ", "))
	}
	fmt.Fprintf(w, `
Next:
  har2mcp inspect %[1]s     # summary of tools and auth, safe to share
  har2mcp generate %[1]s --target go
`, quoteArg(path))
}

// startOrigin is the scheme://host[:port] of the first recording's start
// URL, or "".
func startOrigin(hars []*har.HAR) string {
	for _, h := range hars {
		if m := h.Log.Har2mcp; m != nil && m.StartURL != "" {
			if u, err := url.Parse(m.StartURL); err == nil && u.Host != "" {
				return u.Scheme + "://" + u.Host
			}
		}
	}
	return ""
}
