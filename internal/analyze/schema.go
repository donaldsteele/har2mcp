package analyze

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/donaldsteele/har2mcp/internal/spec"
)

// Limits that keep a spec readable when responses are large.
const (
	exampleArrayItems = 3    // array items kept in an example
	exampleStringLen  = 200  // characters kept per example string
	exampleTextLen    = 2000 // characters kept of a non-JSON example
	schemaMaxDepth    = 12
	schemaMaxProps    = 200
)

// buildResponse describes what an operation returns: the content type, a
// JSON schema inferred from every successful sample, and one example taken
// from the redacted recording. Downloads only get the content type.
func buildResponse(op *operation, download bool) spec.Response {
	var r spec.Response
	var ok []*sample
	for _, s := range op.samples {
		if isSuccess(s.e.Response.Status) {
			ok = append(ok, s)
		}
	}
	from := ok
	if len(from) == 0 {
		from = op.samples
	}
	for _, s := range from {
		if m := responseMIME(s.e); m != "" {
			r.ContentType = m
			break
		}
	}
	if download {
		return r
	}

	var root *schemaNode
	for _, s := range ok {
		if v, isJSON := responseJSON(s.e); isJSON {
			if root == nil {
				root = &schemaNode{}
			}
			root.add(normalizeJSON(v), 0)
		}
	}
	if root != nil {
		r.Schema = root.toMap()
	}

	for _, s := range ok {
		if s.red.Response.Content.Truncated {
			continue
		}
		b, err := s.red.Response.Content.Bytes()
		if err != nil || len(b) == 0 {
			continue
		}
		if v, isJSON := decodeJSON(b); isJSON {
			r.Example = trimExample(normalizeJSON(v), 0)
			break
		}
		if root == nil && isTextual(responseMIME(s.e)) {
			text := string(b)
			if utf8.ValidString(text) {
				r.Example = truncateText(text, exampleTextLen)
				break
			}
		}
	}
	return r
}

func isTextual(m string) bool {
	return strings.HasPrefix(m, "text/") || strings.Contains(m, "xml") || strings.Contains(m, "json") || m == "application/javascript"
}

func truncateText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// trimExample shortens long arrays and strings so examples stay readable.
func trimExample(v any, depth int) any {
	switch x := v.(type) {
	case string:
		return truncateText(x, exampleStringLen)
	case []any:
		if depth > schemaMaxDepth {
			return []any{}
		}
		if len(x) > exampleArrayItems {
			x = x[:exampleArrayItems]
		}
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = trimExample(val, depth+1)
		}
		return out
	case map[string]any:
		if depth > schemaMaxDepth {
			return map[string]any{}
		}
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = trimExample(val, depth+1)
		}
		return out
	default:
		return v
	}
}

// schemaNode accumulates the JSON types seen at one place in the responses.
type schemaNode struct {
	types map[string]bool
	props map[string]*schemaNode
	items *schemaNode
}

func (n *schemaNode) add(v any, depth int) {
	if n.types == nil {
		n.types = map[string]bool{}
	}
	switch x := v.(type) {
	case nil:
		n.types["null"] = true
	case bool:
		n.types["boolean"] = true
	case int64:
		n.types["integer"] = true
	case float64:
		n.types["number"] = true
	case string:
		n.types["string"] = true
	case []any:
		n.types["array"] = true
		if depth >= schemaMaxDepth {
			return
		}
		for _, val := range x {
			if n.items == nil {
				n.items = &schemaNode{}
			}
			n.items.add(val, depth+1)
		}
	case map[string]any:
		n.types["object"] = true
		if depth >= schemaMaxDepth {
			return
		}
		if n.props == nil {
			n.props = map[string]*schemaNode{}
		}
		for _, k := range sortedKeys(x) {
			child := n.props[k]
			if child == nil {
				if len(n.props) >= schemaMaxProps {
					continue
				}
				child = &schemaNode{}
				n.props[k] = child
			}
			child.add(x[k], depth+1)
		}
	}
}

// toMap renders the node as a JSON schema. Integers seen alongside other
// numbers become "number"; several types become a list.
func (n *schemaNode) toMap() map[string]any {
	types := make(map[string]bool, len(n.types))
	for t := range n.types {
		types[t] = true
	}
	if types["integer"] && types["number"] {
		delete(types, "integer")
	}
	list := make([]string, 0, len(types))
	for t := range types {
		list = append(list, t)
	}
	sort.Strings(list)
	m := map[string]any{}
	switch len(list) {
	case 0:
	case 1:
		m["type"] = list[0]
	default:
		anyList := make([]any, len(list))
		for i, t := range list {
			anyList[i] = t
		}
		m["type"] = anyList
	}
	if types["object"] && len(n.props) > 0 {
		props := make(map[string]any, len(n.props))
		for k, child := range n.props {
			props[k] = child.toMap()
		}
		m["properties"] = props
	}
	if types["array"] && n.items != nil {
		m["items"] = n.items.toMap()
	}
	return m
}
