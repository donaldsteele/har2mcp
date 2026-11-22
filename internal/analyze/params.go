package analyze

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// field is one value a request carries.
type field struct {
	loc   string // "query" or "body"
	path  string // query key, form field, multipart part, or dotted JSON path
	value any    // string, int64, float64, bool, nil, []any or map[string]any
}

// filePart is a multipart part carrying a file.
type filePart struct {
	name, fileName, contentType string
	size                        int64 // -1 when unknown
	inferred                    bool  // size comes from the body size, not the bytes
}

type parsedRequest struct {
	bodyType string // none, json, form, multipart, other
	mime     string
	fields   []field
	files    []filePart
	problem  string // why the body cannot be modeled, if it cannot
}

// parseRequest reads the query string and body of a request into fields.
func parseRequest(e *har.Entry, u *url.URL) parsedRequest {
	p := parsedRequest{bodyType: "none"}
	q := u.Query()
	for _, k := range sortedKeys(q) {
		vs := q[k]
		var v any = vs[0]
		if len(vs) > 1 {
			arr := make([]any, len(vs))
			for i, s := range vs {
				arr[i] = s
			}
			v = arr
		}
		p.fields = append(p.fields, field{loc: "query", path: k, value: v})
	}

	pd := e.Request.PostData
	if pd != nil && pd.Truncated && pd.Text == "" && len(pd.Params) == 0 {
		p.bodyType = "other"
		p.problem = "the request body was over the recording cap, so its fields are unknown (record again with a bigger --body-cap)"
		return p
	}
	if pd == nil || (pd.Text == "" && len(pd.Params) == 0) {
		return p
	}
	p.mime = mediaType(pd.MimeType)
	if p.mime == "" {
		p.mime = mediaType(e.Request.Header("Content-Type"))
	}
	switch {
	case p.mime == "multipart/form-data":
		p.bodyType = "multipart"
		parseMultipart(&p, pd)
		inferFileSize(&p, e)
	case p.mime == "application/x-www-form-urlencoded":
		p.bodyType = "form"
		var vals url.Values
		if pd.Text != "" {
			vals, _ = url.ParseQuery(pd.Text)
		} else {
			vals = url.Values{}
			for _, prm := range pd.Params {
				vals.Add(prm.Name, prm.Value)
			}
		}
		for _, k := range sortedKeys(vals) {
			p.fields = append(p.fields, field{loc: "body", path: k, value: vals[k][0]})
		}
	default:
		v, ok := decodeJSON([]byte(pd.Text))
		switch {
		case ok:
			p.bodyType = "json"
			if m, isObj := v.(map[string]any); isObj {
				flattenJSON("", m, &p.fields)
			} else {
				p.problem = "the request body is a JSON array, which har2mcp cannot map to inputs yet"
			}
		case strings.Contains(p.mime, "json"):
			p.bodyType = "other"
			p.problem = "the request body is not valid JSON (it may have been cut off by the recording cap)"
		default:
			p.bodyType = "other"
			m := p.mime
			if m == "" {
				m = "of an unknown type"
			}
			p.problem = fmt.Sprintf("the request body is %s, which har2mcp cannot model yet (it handles JSON, form and multipart bodies)", m)
		}
	}
	return p
}

func parseMultipart(p *parsedRequest, pd *har.PostData) {
	seen := map[string]bool{}
	addField := func(name, value string) {
		if !seen[name] {
			seen[name] = true
			p.fields = append(p.fields, field{loc: "body", path: name, value: value})
		}
	}
	addFile := func(f filePart) {
		if !seen[f.name] {
			seen[f.name] = true
			p.files = append(p.files, f)
		}
	}
	if len(pd.Params) > 0 {
		for _, prm := range pd.Params {
			if prm.FileName != "" {
				size := int64(len(prm.Value))
				if size == 0 {
					size = -1
				}
				addFile(filePart{name: prm.Name, fileName: prm.FileName, contentType: prm.ContentType, size: size})
			} else {
				addField(prm.Name, prm.Value)
			}
		}
		return
	}
	_, params, err := mime.ParseMediaType(pd.MimeType)
	if err != nil || params["boundary"] == "" {
		p.problem = "the multipart body has no boundary, so its parts could not be read"
		return
	}
	r := multipart.NewReader(strings.NewReader(pd.Text), params["boundary"])
	for {
		part, err := r.NextPart()
		if err != nil {
			return
		}
		data, _ := io.ReadAll(io.LimitReader(part, 1<<20))
		if part.FileName() != "" {
			size := int64(len(data))
			if size == 0 {
				size = -1
			}
			addFile(filePart{name: part.FormName(), fileName: part.FileName(), contentType: part.Header.Get("Content-Type"), size: size})
		} else if part.FormName() != "" {
			addField(part.FormName(), string(data))
		}
		part.Close()
	}
}

// inferFileSize works out the size of a multipart upload's one file part
// when the recording has no bytes for it. Chrome leaves file contents out
// of the request body it reports, but the body size (Content-Length) counts
// them, so the file is the difference.
func inferFileSize(p *parsedRequest, e *har.Entry) {
	pd := e.Request.PostData
	if len(p.files) != 1 || p.files[0].size >= 0 || pd == nil || pd.Text == "" || pd.Truncated {
		return
	}
	total := e.Request.BodySize
	if cl, err := strconv.ParseInt(strings.TrimSpace(e.Request.Header("Content-Length")), 10, 64); err == nil && cl > total {
		total = cl
	}
	if n := total - int64(len(pd.Text)); n > 0 {
		p.files[0].size = n
		p.files[0].inferred = true
	}
}

// flattenJSON lists the leaves of a JSON object as dotted paths. Arrays and
// empty objects are leaves.
func flattenJSON(prefix string, m map[string]any, out *[]field) {
	for _, k := range sortedKeys(m) {
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		if sub, ok := m[k].(map[string]any); ok && len(sub) > 0 {
			flattenJSON(p, sub, out)
			continue
		}
		*out = append(*out, field{loc: "body", path: p, value: normalizeJSON(m[k])})
	}
}

// normalizeJSON converts json.Number to int64 or float64, at any depth, so
// values encode with their real type in YAML.
func normalizeJSON(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normalizeJSON(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = normalizeJSON(val)
		}
		return out
	default:
		return v
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// draft is a tool being built, with what naming needs to know.
type draft struct {
	op    *operation
	tool  spec.Tool
	notes []string
	file  string // "", "upload" or "download"
	kind0 string // kind without the step label, for picking a step's primary
}

func (d *draft) note(format string, a ...any) {
	n := fmt.Sprintf(format, a...)
	for _, old := range d.notes {
		if old == n {
			return
		}
	}
	d.notes = append(d.notes, n)
}

// buildTool turns an operation into a tool: request, inputs, file
// handling, response and review notes. Naming and descriptions come later.
func buildTool(rec *recording, op *operation, au *authResult) *draft {
	d := &draft{op: op}
	t := &d.tool
	t.Enabled = true
	t.Request = spec.Request{
		Method:        op.method,
		Path:          op.path,
		Discriminator: strings.Join(op.disc, ","),
	}
	bodyType, problem := op.bodyType()
	if problem != "" {
		d.note("%s; check request.body", problem)
	}
	if bodyType == "other" {
		bodyType = "none"
	}
	t.Request.BodyType = bodyType

	var chunk chunkResult
	if fo := detectFile(op); fo != nil {
		t.File = fo
		d.file = fo.Direction
		if fo.Direction == "upload" {
			chunk = detectChunking(op, fo.Part)
			fo.Chunked = chunk.chunking
			for _, n := range chunk.notes {
				d.note("%s", n)
			}
		}
	}

	taken := map[string]bool{}
	var inputs []spec.Input
	for i, name := range op.params {
		vals := op.pathValues(i)
		typ := inferType(vals, "path", "")
		taken[name] = true
		inputs = append(inputs, spec.Input{Name: name, Type: typ, Required: true, In: "path", Field: name, Example: example(vals, typ)})
	}
	if d.file == "upload" {
		taken["local_path"] = true
		inputs = append(inputs, spec.Input{
			Name: "local_path", Type: "string", Required: true, In: "file", Field: t.File.Part,
			Description: "Path of the local file to upload, relative to the server's files directory.",
		})
	}
	inputs = append(inputs, decideFields(rec, op, au, d, chunk.fields, taken)...)
	if d.file == "download" {
		inputs = append(inputs, spec.Input{
			Name: uniqueInput("local_path", taken), Type: "string", Required: true, In: "file",
			Description: "Where to save the downloaded file, relative to the server's files directory.",
		})
	}
	t.Inputs = inputs
	t.Request.Headers = fixedHeaders(op, au)
	t.Response = buildResponse(op, d.file == "download")
	if !op.anySuccess() {
		d.note("no successful response was recorded (status %s); check that this call works", op.statuses())
	}
	t.Source = spec.Source{Key: op.key, Samples: len(op.samples)}
	d.kind0 = classify(d, "")
	return d
}

// fieldStat is one field across an operation's samples.
type fieldStat struct {
	loc, path string
	vals      []any
	smps      []*sample
}

func collectFields(op *operation) []*fieldStat {
	idx := map[string]*fieldStat{}
	var out []*fieldStat
	for _, s := range op.samples {
		for _, f := range s.req.fields {
			k := f.loc + "\x00" + f.path
			fs := idx[k]
			if fs == nil {
				fs = &fieldStat{loc: f.loc, path: f.path}
				idx[k] = fs
				out = append(out, fs)
			}
			fs.vals = append(fs.vals, f.value)
			fs.smps = append(fs.smps, s)
		}
	}
	return out
}

// decideFields sorts each query and body field into an input or a fixed
// value (written into the tool's request), and notes values it cannot judge.
func decideFields(rec *recording, op *operation, au *authResult, d *draft, chunkFields map[string]bool, taken map[string]bool) []spec.Input {
	t := &d.tool
	n := len(op.samples)
	var inputs []spec.Input
	input := func(fs *fieldStat, required bool, desc string, withExample bool) {
		typ := inferType(fs.vals, fs.loc, t.Request.BodyType)
		in := spec.Input{
			Name:        inputName(fs.path, taken),
			Type:        typ,
			Description: desc,
			Required:    required,
			In:          fs.loc,
			Field:       fs.path,
		}
		if withExample {
			in.Example = example(fs.vals, typ)
		}
		inputs = append(inputs, in)
	}
	fixedAs := func(fs *fieldStat, v any) {
		if fs.loc == "query" {
			if t.Request.Query == nil {
				t.Request.Query = map[string]any{}
			}
			t.Request.Query[fs.path] = v
			return
		}
		if t.Request.Body == nil {
			t.Request.Body = map[string]any{}
		}
		if t.Request.BodyType == "json" {
			setDotted(t.Request.Body, fs.path, v)
		} else {
			t.Request.Body[fs.path] = v
		}
	}
	fixed := func(fs *fieldStat) { fixedAs(fs, fs.vals[0]) }

	for _, fs := range collectFields(op) {
		present := len(fs.smps) == n
		switch {
		case op.isDiscriminator(fs.path):
			fixed(fs)
			continue
		case au.isCarrier(fs.loc, fs.path):
			continue
		case fs.loc == "body" && chunkFields[fs.path]:
			continue
		}
		if ph := cacheBuster(fs); ph != "" {
			fixedAs(fs, ph)
			continue
		}
		label, password, typedOK := rec.typedMatch(fs, au.loginSteps)
		switch {
		case !typedOK && isSessionTokenField(fs.path) && allTokenish(fs.vals):
			// A session token whose source was not found: Claude cannot
			// know it, so it is never an input.
			d.note("%s field %q looks like a session token, but har2mcp did not find which response it comes from, so it is left out of the request; describe it in auth.session.tokens, or make it an input", fs.loc, fs.path)
		case isSecretField(fs.path) || password:
			input(fs, present, label, false)
		case d.file != "" && isPathLike(fs):
			input(fs, present, label, true)
		case typedOK:
			input(fs, present, label, true)
		case distinctCount(fs.vals) >= 2:
			input(fs, present, "", true)
		case n == 1:
			if rec.responseTraced(fs) {
				input(fs, true, "", true)
			} else {
				fixed(fs)
				d.note("%s field %q was seen in only one request, so it is sent as recorded; make it an input if it should change", fs.loc, fs.path)
			}
		case !present:
			input(fs, false, "", true)
		default:
			fixed(fs)
		}
	}
	return inputs
}

// typedMatch reports whether a field carried a value the user typed, and
// returns that form field's label and whether it holds a secret. A value
// typed in the same step always counts; one typed in another step counts
// when it is at least 3 characters, so short values do not match by chance,
// and was not typed while logging in (loginSteps): a user name such as
// "admin" is not the "group: admin" of a later request.
func (rec *recording) typedMatch(fs *fieldStat, loginSteps map[int]bool) (label string, password, ok bool) {
	for pass := 0; pass < 2; pass++ {
		for i, v := range fs.vals {
			str, isScalar := scalarString(v)
			if !isScalar || str == "" {
				continue
			}
			s := fs.smps[i]
			for _, tv := range rec.typed {
				if strings.TrimSpace(tv.input.Value) != str {
					continue
				}
				same := s.step >= 0 && tv.step == s.step
				if (pass == 0 && !same) || (pass == 1 && (len(str) < 3 || loginSteps[tv.step])) {
					continue
				}
				return typedLabel(tv.input), har.IsSecretInput(tv.input), true
			}
		}
	}
	return "", false, false
}

// allTokenish reports whether every value looks like a session token.
func allTokenish(vals []any) bool {
	for _, v := range vals {
		s, ok := v.(string)
		if !ok || !looksTokenish(s) {
			return false
		}
	}
	return len(vals) > 0
}

// cacheBusterNames are query parameters that scripts fill with the time or
// a random number so the browser does not cache the response: jQuery's
// "_", ExtJS's "_dc" and the like. "time" is left out: it is as often a
// time the user picked.
var cacheBusterNames = map[string]bool{
	"_": true, "_dc": true, "_t": true, "t": true, "ts": true, "_ts": true, "timestamp": true,
	"nocache": true, "_nocache": true, "cachebuster": true, "cb": true, "_cb": true, "rnd": true, "_rnd": true,
	"rand": true, "random": true, "r": true, "_r": true,
}

// cacheBuster returns the placeholder that replaces a cache-busting query
// parameter: {{now_ms}} or {{now_s}} for the current time in milliseconds
// or seconds, {{random}} for a random number between 0 and 1. The generated
// server fills it in on every call. It returns "" for other fields.
//
// A time stamped by a script grows from one request to the next, so a time
// that goes back between two requests of one recording was chosen by the
// user and is not a cache buster.
func cacheBuster(fs *fieldStat) string {
	if fs.loc != "query" || !cacheBusterNames[strings.ToLower(fs.path)] {
		return ""
	}
	kind := ""
	type stamp struct {
		har, seq int
		n        int64
	}
	var stamps []stamp
	for i, v := range fs.vals {
		s, ok := scalarString(v)
		if !ok {
			return ""
		}
		k := ""
		n, err := strconv.ParseInt(s, 10, 64)
		switch {
		case err == nil && len(s) == 13 && n >= 1e12 && n < 4.2e12:
			k = "{{now_ms}}"
		case err == nil && len(s) == 10 && n >= 1e9 && n < 4.2e9:
			k = "{{now_s}}"
		case strings.HasPrefix(s, "0.") && len(s) >= 6:
			if f, err := strconv.ParseFloat(s, 64); err == nil && f > 0 && f < 1 {
				k = "{{random}}"
			}
		}
		if k == "" || (kind != "" && k != kind) {
			return ""
		}
		kind = k
		if i < len(fs.smps) {
			stamps = append(stamps, stamp{fs.smps[i].har, fs.smps[i].seq, n})
		}
	}
	if kind != "{{random}}" {
		sort.Slice(stamps, func(i, j int) bool {
			if stamps[i].har != stamps[j].har {
				return stamps[i].har < stamps[j].har
			}
			return stamps[i].seq < stamps[j].seq
		})
		for i := 1; i < len(stamps); i++ {
			if stamps[i].har == stamps[i-1].har && stamps[i].n < stamps[i-1].n {
				return ""
			}
		}
	}
	return kind
}

func typedLabel(in har.TypedInput) string {
	s := strings.Join(strings.Fields(in.Label), " ")
	if s == "" {
		s = strings.Join(strings.Fields(strings.NewReplacer("-", " ", "_", " ").Replace(in.Name)), " ")
	}
	return truncateRunes(s, 80)
}

// truncateRunes cuts s to at most n runes.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// responseTraced reports whether a value seen once was returned by an
// earlier response (an item picked from a list), which makes it an input.
func (rec *recording) responseTraced(fs *fieldStat) bool {
	str, ok := fs.vals[0].(string)
	if !ok || len(str) < 3 {
		return false
	}
	switch strings.ToLower(str) {
	case "true", "false", "null", "none", "yes", "no", "off":
		return false
	}
	s := fs.smps[0]
	seq, seen := rec.respStrings[s.har][str]
	return seen && seq < s.seq
}

var pathLikeRE = regexp.MustCompile(`(?i)path|file|folder|dir|dest|target|src|source|location|name`)

// isPathLike reports whether a file tool's field names a remote file or
// folder; those are always inputs.
func isPathLike(fs *fieldStat) bool {
	if pathLikeRE.MatchString(lastSegment(fs.path)) {
		return true
	}
	for _, v := range fs.vals {
		if s, ok := v.(string); ok && (strings.Contains(s, "/") || strings.Contains(s, `\`)) {
			return true
		}
	}
	return false
}

// scalarString is a scalar value as text, for comparing with typed values.
func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	}
	return "", false
}

func distinctCount(vals []any) int {
	seen := map[string]bool{}
	for _, v := range vals {
		b, _ := json.Marshal(v)
		seen[string(b)] = true
	}
	return len(seen)
}

var inputNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// inputName names an input after its field: the last part of a dotted
// path, or the whole path when that is taken.
func inputName(path string, taken map[string]bool) string {
	clean := func(s string) string {
		if inputNameRE.MatchString(s) {
			return s
		}
		return spec.SanitizeName(s, 64)
	}
	name := clean(lastSegment(path))
	if taken[name] {
		name = clean(strings.ReplaceAll(path, ".", "_"))
	}
	return uniqueInput(name, taken)
}

// uniqueInput returns name, or name_2, name_3 ... when it is taken,
// shortening name so the result stays within 64 characters, and records it.
func uniqueInput(name string, taken map[string]bool) string {
	out := name
	for i := 2; taken[out]; i++ {
		suffix := fmt.Sprintf("_%d", i)
		base := name
		if len(base)+len(suffix) > 64 {
			base = strings.TrimRight(base[:64-len(suffix)], "_")
		}
		out = base + suffix
	}
	taken[out] = true
	return out
}

func lastSegment(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// inferType gives a JSON schema type for an input from its recorded values.
// Query, form and multipart values are text, so canonical integers and
// true/false count as integer and boolean there; JSON strings stay strings.
func inferType(vals []any, loc, bodyType string) string {
	textual := loc == "query" || loc == "path" || bodyType == "form" || bodyType == "multipart"
	types := map[string]bool{}
	for _, v := range vals {
		switch x := v.(type) {
		case nil:
		case bool:
			types["boolean"] = true
		case int64:
			types["integer"] = true
		case float64:
			types["number"] = true
		case []any:
			types["array"] = true
		case map[string]any:
			types["object"] = true
		case string:
			switch {
			case textual && isCanonicalInt(x):
				types["integer"] = true
			case textual && (x == "true" || x == "false"):
				types["boolean"] = true
			default:
				types["string"] = true
			}
		}
	}
	switch {
	case len(types) == 0:
		return "string"
	case len(types) == 1:
		for t := range types {
			return t
		}
	case len(types) == 2 && types["integer"] && types["number"]:
		return "number"
	}
	return "string"
}

func isCanonicalInt(s string) bool {
	i, err := strconv.ParseInt(s, 10, 64)
	return err == nil && strconv.FormatInt(i, 10) == s
}

// example is the first recorded value, converted to the input's type.
func example(vals []any, typ string) any {
	for _, v := range vals {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok {
			switch typ {
			case "integer":
				if i, err := strconv.ParseInt(s, 10, 64); err == nil {
					return i
				}
			case "boolean":
				return s == "true"
			}
		}
		return v
	}
	return nil
}

// setDotted sets m[a][b][c] = v for the path "a.b.c".
func setDotted(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		sub, ok := m[p].(map[string]any)
		if !ok {
			sub = map[string]any{}
			m[p] = sub
		}
		m = sub
	}
	m[parts[len(parts)-1]] = v
}

var standardHeaders = map[string]bool{
	"accept": true, "accept-encoding": true, "accept-language": true, "cache-control": true,
	"connection": true, "content-length": true, "content-type": true, "cookie": true, "host": true,
	"origin": true, "pragma": true, "referer": true, "user-agent": true, "dnt": true,
	"upgrade-insecure-requests": true, "priority": true, "te": true, "if-none-match": true,
	"if-modified-since": true, "if-match": true, "if-unmodified-since": true, "if-range": true,
	"range": true, "keep-alive": true, "expect": true, "purpose": true, "x-client-data": true,
	"proxy-connection": true, "proxy-authorization": true, "authorization": true,
	"content-encoding": true, "transfer-encoding": true, "trailer": true, "via": true,
	"forwarded": true, "upgrade": true, "x-devtools-emulate-network-conditions-client-id": true,
}

func isStandardHeader(name string) bool {
	n := strings.ToLower(name)
	return standardHeaders[n] || strings.HasPrefix(n, "sec-") || strings.HasPrefix(n, ":") ||
		strings.HasPrefix(n, "x-forwarded-") || strings.HasPrefix(n, "access-control-request-")
}

// fixedHeaders returns the non-standard headers every sample sent with the
// same value, leaving out session tokens and anything that looks secret.
func fixedHeaders(op *operation, au *authResult) map[string]string {
	type hv struct {
		name, value string
		count       int
		varies      bool
	}
	seen := map[string]*hv{}
	var order []string
	for _, s := range op.samples {
		inSample := map[string]bool{}
		for _, h := range s.e.Request.Headers {
			ln := strings.ToLower(h.Name)
			if inSample[ln] || isStandardHeader(ln) || isSecretHeader(ln) || au.isCarrier("header", ln) {
				continue
			}
			inSample[ln] = true
			x := seen[ln]
			if x == nil {
				x = &hv{name: h.Name, value: h.Value}
				seen[ln] = x
				order = append(order, ln)
			} else if x.value != h.Value {
				x.varies = true
			}
			x.count++
		}
	}
	var out map[string]string
	for _, ln := range order {
		x := seen[ln]
		if x.varies || x.count != len(op.samples) {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[x.name] = x.value
	}
	return out
}
