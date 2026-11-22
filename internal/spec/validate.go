package spec

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var (
	serviceNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	toolNameRE    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	inputNameRE   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	methodRE      = regexp.MustCompile(`^[A-Z]+$`)
	placeholderRE = regexp.MustCompile(`\{([^{}/]*)\}`)
)

var (
	authModes  = []string{"none", "http", "browser", "basic"}
	toolKinds  = []string{"read", "change", "destructive"}
	inputTypes = []string{"string", "integer", "number", "boolean", "array", "object"}
	inputIns   = []string{"path", "query", "body", "file"}
	bodyTypes  = []string{"none", "json", "form", "multipart"}
	directions = []string{"upload", "download"}
)

func oneOf(v string, set []string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

// Placeholders returns the {placeholder} names in a request path, in order.
func Placeholders(path string) []string {
	var out []string
	for _, m := range placeholderRE.FindAllStringSubmatch(path, -1) {
		out = append(out, m[1])
	}
	return out
}

// Validate checks the spec and returns every problem found, one per line,
// each naming the field it is about.
func (s *Spec) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if s.Har2mcp != 0 && s.Har2mcp != FormatVersion {
		add("har2mcp: format %d is not supported (want %d)", s.Har2mcp, FormatVersion)
	}
	if !serviceNameRE.MatchString(s.Service.Name) {
		add("service.name %q must be lower case letters, digits and _, start with a letter, and be at most 32 characters", s.Service.Name)
	}

	a := &s.Auth
	if !oneOf(a.Mode, authModes) {
		add("auth.mode %q must be one of %s", a.Mode, strings.Join(authModes, ", "))
	}
	if a.Mode == "http" || a.Mode == "browser" {
		if a.Login == nil {
			add("auth.login is required when auth.mode is %q", a.Mode)
		}
	}
	if a.Login != nil {
		if a.Mode == "http" {
			if !methodRE.MatchString(a.Login.Request.Method) {
				add("auth.login.request.method %q must be an upper-case HTTP method", a.Login.Request.Method)
			}
			if !strings.HasPrefix(a.Login.Request.Path, "/") {
				add("auth.login.request.path %q must start with /", a.Login.Request.Path)
			}
		}
		if a.Login.Request.BodyType != "" && !oneOf(a.Login.Request.BodyType, bodyTypes) {
			add("auth.login.request.body_type %q must be one of %s", a.Login.Request.BodyType, strings.Join(bodyTypes, ", "))
		}
		if a.Mode == "browser" {
			f := a.Login.Form
			if f == nil {
				add("auth.login.form is required when auth.mode is \"browser\"")
			} else if f.Username == "" || f.Password == "" {
				add("auth.login.form needs the username and password field selectors in browser mode")
			}
		}
	}
	tokenPaths := map[string]bool{}
	for i, tf := range a.Session.Tokens {
		where := fmt.Sprintf("auth.session.tokens[%d] (%s)", i, tf.Name)
		if n := tf.From.count(); n != 1 {
			add("%s: from must set exactly one of response_json, response_text, response_header, cookie, header, query, body (has %d)", where, n)
		}
		if n := tf.To.count(); n != 1 {
			add("%s: to must set exactly one of header, query, body, cookie, path (has %d)", where, n)
		}
		if tf.From.Path != "" {
			add("%s: from.path is not a token source; path is only used in to", where)
		}
		if tf.To.ResponseText != "" {
			add("%s: to.response_text is not a place to send a token; response_text is only used in from", where)
		}
		if tf.From.ResponseText != "" {
			if re, err := regexp.Compile(tf.From.ResponseText); err != nil {
				add("%s: from.response_text is not a valid regular expression: %v", where, err)
			} else if re.NumSubexp() < 1 {
				add("%s: from.response_text needs a group, such as <SID>([0-9a-f]+)</SID>, around the token", where)
			}
		}
		if tf.To.Path != "" {
			if strings.ContainsAny(tf.To.Path, "{}/") {
				add("%s: to.path %q is a placeholder name, without braces or slashes", where, tf.To.Path)
			}
			tokenPaths[tf.To.Path] = true
		}
		if r := tf.Request; r != nil {
			if !methodRE.MatchString(r.Method) {
				add("%s: request.method %q must be an upper-case HTTP method", where, r.Method)
			}
			if !strings.HasPrefix(r.Path, "/") {
				add("%s: request.path %q must start with /", where, r.Path)
			}
			if r.BodyType != "" && !oneOf(r.BodyType, bodyTypes) {
				add("%s: request.body_type %q must be one of %s", where, r.BodyType, strings.Join(bodyTypes, ", "))
			}
		}
		if strings.ContainsFunc(tf.Prefix, unicode.IsControl) {
			add("auth.session.tokens[%d] (%s): prefix must not contain control characters such as newlines", i, tf.Name)
		}
	}
	for _, code := range a.ReloginOn {
		if code < 100 || code > 599 {
			add("auth.relogin_on: %d is not an HTTP status code", code)
		}
	}

	seen := map[string]int{}
	for i := range s.Tools {
		t := &s.Tools[i]
		where := fmt.Sprintf("tools[%d] %q", i, t.Name)
		if !toolNameRE.MatchString(t.Name) {
			add("%s: name must be lower case letters, digits and _, start with a letter, and be at most 64 characters", where)
		}
		if j, dup := seen[t.Name]; dup {
			add("%s: duplicate tool name (also tools[%d])", where, j)
		} else {
			seen[t.Name] = i
		}
		if !oneOf(t.Kind, toolKinds) {
			add("%s: kind %q must be one of %s", where, t.Kind, strings.Join(toolKinds, ", "))
		}
		errs = append(errs, t.validateRequest(where, tokenPaths)...)
	}
	return errors.Join(errs...)
}

func (r TokenRef) count() int {
	n := 0
	for _, v := range []string{r.ResponseJSON, r.ResponseText, r.ResponseHeader, r.Cookie, r.Header, r.Query, r.Body, r.Path} {
		if v != "" {
			n++
		}
	}
	return n
}

// validateRequest checks a tool's request, inputs and file settings.
// tokenPaths are the path placeholders that session tokens fill.
func (t *Tool) validateRequest(where string, tokenPaths map[string]bool) []error {
	var errs []error
	add := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf(where+": "+format, a...))
	}
	r := &t.Request
	if !methodRE.MatchString(r.Method) {
		add("request.method %q must be an upper-case HTTP method", r.Method)
	}
	if !strings.HasPrefix(r.Path, "/") {
		add("request.path %q must start with /", r.Path)
	}
	if r.BodyType != "" && !oneOf(r.BodyType, bodyTypes) {
		add("request.body_type %q must be one of %s", r.BodyType, strings.Join(bodyTypes, ", "))
	}

	names := map[string]bool{}
	pathFields := map[string]bool{}
	fileInputs := 0
	for j, in := range t.Inputs {
		iw := fmt.Sprintf("inputs[%d] %q", j, in.Name)
		if !inputNameRE.MatchString(in.Name) {
			add("%s: name must be letters, digits and _, start with a letter, and be at most 64 characters", iw)
		}
		if names[in.Name] {
			add("%s: duplicate input name", iw)
		}
		names[in.Name] = true
		if !oneOf(in.Type, inputTypes) {
			add("%s: type %q must be one of %s", iw, in.Type, strings.Join(inputTypes, ", "))
		}
		if !oneOf(in.In, inputIns) {
			add("%s: in %q must be one of %s", iw, in.In, strings.Join(inputIns, ", "))
		}
		switch in.In {
		case "path":
			pathFields[in.pathField()] = true
		case "file":
			fileInputs++
		}
	}
	placeholders := map[string]bool{}
	for _, p := range Placeholders(r.Path) {
		placeholders[p] = true
		if !pathFields[p] && !tokenPaths[p] {
			add("request.path placeholder {%s} has no input with in: path and field: %s", p, p)
		}
	}
	for _, in := range t.Inputs {
		if in.In == "path" && !placeholders[in.pathField()] {
			add("input %q has in: path but request.path %q has no {%s} placeholder", in.Name, r.Path, in.pathField())
		}
	}

	if f := t.File; f != nil {
		if !oneOf(f.Direction, directions) {
			add("file.direction %q must be upload or download", f.Direction)
		}
		if f.Direction == "upload" && f.Part == "" {
			add("file.part (the multipart part carrying the file) is required for uploads")
		}
		if fileInputs != 1 {
			add("a file tool needs exactly one input with in: file (the local path), has %d", fileInputs)
		}
		if c := f.Chunked; c != nil {
			if c.ChunkSize <= 0 {
				add("file.chunked.chunk_size must be positive")
			}
			if c.IndexBase < 0 {
				add("file.chunked.index_base must be 0 or more")
			}
			if c.OffsetField == "" && c.IndexField == "" {
				add("file.chunked needs offset_field or index_field")
			}
		}
	} else if fileInputs > 0 {
		add("inputs with in: file are only allowed on file tools (set file:)")
	}
	return errs
}

// pathField is the placeholder an in: path input fills: Field, or Name when
// Field is empty.
func (in Input) pathField() string {
	if in.Field != "" {
		return in.Field
	}
	return in.Name
}
