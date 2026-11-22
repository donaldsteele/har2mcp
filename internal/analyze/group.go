package analyze

import (
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/donaldsteele/har2mcp/internal/spec"
)

// operation is a group of samples that are the same call: one method, one
// normalized path and one discriminator value. Each becomes a tool.
type operation struct {
	key      string // spec.Source.Key: "POST /api.php act=getdisklist"
	method   string
	path     string   // normalized, with {placeholder} segments
	params   []string // placeholder names, in path order
	disc     []string // discriminator fields ("act"); several for APIs like api=X&method=Y
	discVals []string
	samples  []*sample
	pvals    [][]string // per sample, the placeholder values (unescaped)
}

// discriminatorNames are the body or query fields that name the action on
// an RPC-style endpoint, in priority order.
var discriminatorNames = []string{"operationName", "act", "action", "cmd", "command", "method", "api", "func", "function", "op", "operation"}

var (
	uuidRE   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRE    = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	opaqueRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,}$`)
)

// isIDLike reports whether a path segment looks like an identifier: a
// number, a UUID, a hash, or a long opaque token.
func isIDLike(seg string) bool {
	if seg == "" {
		return false
	}
	if strings.Trim(seg, "0123456789") == "" {
		return true
	}
	hasDigit := strings.ContainsAny(seg, "0123456789")
	hasLetter := strings.IndexFunc(seg, func(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }) >= 0
	switch {
	case uuidRE.MatchString(seg):
		return true
	case hexRE.MatchString(seg) && hasDigit:
		return true
	case opaqueRE.MatchString(seg) && hasDigit && hasLetter:
		return true
	}
	return false
}

type preOp struct {
	s    *sample
	segs []string // escaped path segments; segs[0] is "" for the leading "/"
	mask []bool   // segment is a placeholder
	disc []string
	vals []string
}

func unescapeSeg(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// group sorts samples into operations, in order of first appearance.
//
// Path segments that look like IDs become placeholders. So does a segment
// that takes several values across otherwise identical paths when every one
// of those values was returned by some response (an item picked from a
// list), which tells /disks/sda and /disks/sdb apart from /disks and
// /shares. Session tokens in the path (pathTokens, token value ->
// placeholder name) are replaced with their placeholder first, so a new
// session gives the same operations.
func group(rec *recording, calls []*sample, pathTokens map[string]string) []*operation {
	pres := make([]*preOp, 0, len(calls))
	for _, s := range calls {
		p := rewritePathTokens(s.u.EscapedPath(), pathTokens)
		if p == "" {
			p = "/"
		}
		po := &preOp{s: s, segs: strings.Split(p, "/")}
		po.mask = make([]bool, len(po.segs))
		for i := 1; i < len(po.segs); i++ {
			po.mask[i] = isIDLike(unescapeSeg(po.segs[i]))
		}
		po.disc, po.vals = discriminators(s.req)
		pres = append(pres, po)
	}

	buckets := map[string][]*preOp{}
	var bucketOrder []string
	for _, po := range pres {
		k := po.s.e.Request.Method + "|" + strconv.Itoa(len(po.segs)) + "|" + strings.Join(po.disc, ",") + "=" + strings.Join(po.vals, ",")
		if _, ok := buckets[k]; !ok {
			bucketOrder = append(bucketOrder, k)
		}
		buckets[k] = append(buckets[k], po)
	}
	for _, k := range bucketOrder {
		mergeVaryingSegments(rec, buckets[k])
	}

	ops := map[string]*operation{}
	var order []*operation
	for _, po := range pres {
		path, names, values := renderPath(po)
		method := strings.ToUpper(po.s.e.Request.Method)
		key := method + " " + path
		for i, f := range po.disc {
			key += " " + f + "=" + po.vals[i]
		}
		op := ops[key]
		if op == nil {
			op = &operation{key: key, method: method, path: path, params: names, disc: po.disc, discVals: po.vals}
			ops[key] = op
			order = append(order, op)
		}
		op.samples = append(op.samples, po.s)
		op.pvals = append(op.pvals, values)
	}
	return order
}

// mergeVaryingSegments masks positions where samples differ only in that
// segment and every differing value appeared in a response.
func mergeVaryingSegments(rec *recording, bucket []*preOp) {
	if len(bucket) < 2 {
		return
	}
	n := len(bucket[0].segs)
	for changed := true; changed; {
		changed = false
		for pos := 1; pos < n; pos++ {
			groups := map[string][]*preOp{}
			var keys []string
			for _, po := range bucket {
				if po.mask[pos] {
					continue
				}
				var b strings.Builder
				for i, seg := range po.segs {
					switch {
					case i == pos:
						b.WriteString("\x01")
					case po.mask[i]:
						b.WriteString("\x00")
					default:
						b.WriteString(seg)
					}
					b.WriteByte('/')
				}
				k := b.String()
				if _, ok := groups[k]; !ok {
					keys = append(keys, k)
				}
				groups[k] = append(groups[k], po)
			}
			for _, k := range keys {
				g := groups[k]
				distinct := map[string]bool{}
				for _, po := range g {
					distinct[unescapeSeg(po.segs[pos])] = true
				}
				if len(distinct) < 2 || !rec.allReturned(distinct) {
					continue
				}
				for _, po := range g {
					po.mask[pos] = true
				}
				changed = true
			}
		}
	}
}

// allReturned reports whether every value appeared in some JSON response.
func (rec *recording) allReturned(vals map[string]bool) bool {
	for v := range vals {
		if v == "" {
			return false
		}
		found := false
		for _, m := range rec.respStrings {
			if _, ok := m[v]; ok {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// renderPath writes the normalized path and returns the placeholder names
// and this sample's values for them. One placeholder is "id"; several are
// named after the segment before each ("/users/{user_id}/keys/{key_id}").
func renderPath(po *preOp) (string, []string, []string) {
	var positions []int
	for i, m := range po.mask {
		if m {
			positions = append(positions, i)
		}
	}
	names := make([]string, len(positions))
	taken := map[string]bool{}
	for j, pos := range positions {
		name := "id"
		if len(positions) > 1 && pos > 1 && !po.mask[pos-1] {
			if prev := spec.SanitizeName(singular(unescapeSeg(po.segs[pos-1])), 60); prev != "unnamed" {
				name = prev + "_id"
			}
		}
		names[j] = uniqueInput(name, taken)
	}
	segs := append([]string(nil), po.segs...)
	values := make([]string, len(positions))
	for j, pos := range positions {
		values[j] = unescapeSeg(segs[pos])
		segs[pos] = "{" + names[j] + "}"
	}
	p := strings.Join(segs, "/")
	if p == "" {
		p = "/"
	}
	return p, names, values
}

func singular(s string) string {
	ls := strings.ToLower(s)
	switch {
	case strings.HasSuffix(ls, "ies") && len(s) > 4:
		return s[:len(s)-3] + "y"
	case strings.HasSuffix(ls, "sses"), strings.HasSuffix(ls, "xes"):
		return s[:len(s)-2]
	case strings.HasSuffix(ls, "s") && !strings.HasSuffix(ls, "ss") && len(s) > 3:
		return s[:len(s)-1]
	}
	return s
}

// discriminators returns the action fields of an RPC-style request and
// their values, in priority order. Only top-level scalar fields count.
func discriminators(r parsedRequest) (fields, vals []string) {
	for _, want := range discriminatorNames {
		for _, loc := range []string{"body", "query"} {
			found := false
			for _, f := range r.fields {
				if f.loc != loc || !strings.EqualFold(f.path, want) {
					continue
				}
				if v, ok := discriminatorValue(f.value); ok {
					fields = append(fields, f.path)
					vals = append(vals, v)
					found = true
				}
				break
			}
			if found {
				break
			}
		}
	}
	return fields, vals
}

func discriminatorValue(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		if x == "" || len(x) > 80 || strings.ContainsAny(x, "\r\n\t") {
			return "", false
		}
		return x, true
	case int64:
		return strconv.FormatInt(x, 10), true
	}
	return "", false
}

func (op *operation) containsAny(set map[*sample]bool) bool {
	for _, s := range op.samples {
		if set[s] {
			return true
		}
	}
	return false
}

func (op *operation) isDiscriminator(path string) bool {
	for _, f := range op.disc {
		if f == path {
			return true
		}
	}
	return false
}

// pathValues returns placeholder i's value in each sample.
func (op *operation) pathValues(i int) []any {
	out := make([]any, len(op.pvals))
	for j, vals := range op.pvals {
		out[j] = vals[i]
	}
	return out
}

// bodyType is the body type most samples used, and why it cannot be
// modeled if it cannot.
func (op *operation) bodyType() (string, string) {
	count := map[string]int{}
	best := ""
	for _, s := range op.samples {
		bt := s.req.bodyType
		count[bt]++
		if best == "" || count[bt] > count[best] {
			best = bt
		}
	}
	for _, s := range op.samples {
		if s.req.bodyType == best && s.req.problem != "" {
			return best, s.req.problem
		}
	}
	return best, ""
}

func isSuccess(status int) bool { return status >= 200 && status < 300 }

func (op *operation) anySuccess() bool {
	for _, s := range op.samples {
		if isSuccess(s.e.Response.Status) {
			return true
		}
	}
	return false
}

func (op *operation) statuses() string {
	seen := map[int]bool{}
	var list []int
	for _, s := range op.samples {
		if st := s.e.Response.Status; !seen[st] {
			seen[st] = true
			list = append(list, st)
		}
	}
	sort.Ints(list)
	parts := make([]string, len(list))
	for i, st := range list {
		parts[i] = strconv.Itoa(st)
	}
	return strings.Join(parts, ", ")
}
