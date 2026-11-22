package spec

import (
	"fmt"
	"strings"
)

// inputHashPrefix starts the Tool.Generated keys that hold one input's hash:
// "input:<in>:<field>". They let Merge tell which inputs were edited.
const inputHashPrefix = "input:"

// inputKey identifies an input by where it goes: "<in>:<field>", or
// "<in>:<name>" for an input with no field (a download's local path).
func inputKey(in Input) string {
	f := in.Field
	if f == "" {
		f = in.Name
	}
	return in.In + ":" + f
}

// mergeInputs merges a tool's inputs one by one, keyed on where each goes
// (in and field), so that editing one input (enhance edits descriptions)
// does not freeze the whole list:
//
//   - an input in both specs takes the fresh one, unless the user edited
//     it, in which case it is kept as is
//   - an input analysis newly made is added
//   - an input the user added is kept
//   - an input analysis made before but no longer makes is dropped, unless
//     the user edited it
//   - an input the user deleted stays deleted; its field goes back into the
//     request as a fixed value (from the existing spec, or the fresh
//     example), and the tool is flagged for review
//
// Specs written before inputs had their own hashes (no "input:" keys in
// Generated) cannot tell edited inputs or deleted ones apart: every
// existing input is kept as is, and the fresh inputs that are missing are
// added. m is the merged tool, a copy of the fresh one; it gets the result.
func mergeInputs(old, fresh *Tool, m *Tool) {
	if !edited(old, "inputs") {
		m.Inputs = append([]Input(nil), fresh.Inputs...)
		return
	}
	perInput := false
	for k := range old.Generated {
		if strings.HasPrefix(k, inputHashPrefix) {
			perInput = true
			break
		}
	}
	freshBy := map[string]Input{}
	for _, in := range fresh.Inputs {
		freshBy[inputKey(in)] = in
	}
	// generatedAs reports whether analysis made the input at key k last
	// time, and whether in is unchanged since.
	generatedAs := func(k string, in *Input) (made, unchanged bool) {
		h, ok := old.Generated[inputHashPrefix+k]
		if !ok {
			return false, false
		}
		return true, in != nil && FieldHash(*in) == h
	}

	var out []Input
	used := map[string]bool{}
	for _, oi := range old.Inputs {
		k := inputKey(oi)
		fi, inFresh := freshBy[k]
		made, unchanged := generatedAs(k, &oi)
		switch {
		case used[k]:
			continue
		case inFresh && perInput && unchanged:
			out = append(out, fi)
		case inFresh:
			out = append(out, oi)
		case perInput && made && unchanged:
			continue // analysis no longer makes it an input
		default:
			out = append(out, oi)
		}
		used[k] = true
	}
	for _, fi := range fresh.Inputs {
		k := inputKey(fi)
		if used[k] {
			continue
		}
		used[k] = true
		if made, _ := generatedAs(k, nil); perInput && made && fi.In != "path" && fi.In != "file" {
			// The user deleted this input: send its field as a fixed value.
			v, ok := fixedValue(old.Request, fi)
			if !ok {
				v, ok = fi.Example, fi.Example != nil
			}
			if ok {
				setFixed(&m.Request, fi, v)
				m.Review = true
				m.ReviewNotes = append(m.ReviewNotes, fmt.Sprintf("input %q was deleted by hand, so %s field %q is sent as the fixed value %v; analysis sees it change between requests, so check it", fi.Name, fi.In, fi.Field, v))
			} else {
				m.Review = true
				m.ReviewNotes = append(m.ReviewNotes, fmt.Sprintf("input %q was deleted by hand, so %s field %q is not sent; analysis sees it change between requests, so check it", fi.Name, fi.In, fi.Field))
			}
			continue
		}
		out = append(out, fi)
	}

	// Input names stay unique: the user's names win.
	taken := map[string]bool{}
	for i := range out {
		if _, isOld := findInput(old.Inputs, inputKey(out[i])); isOld {
			taken[out[i].Name] = true
		}
	}
	for i := range out {
		if _, isOld := findInput(old.Inputs, inputKey(out[i])); !isOld {
			out[i].Name = UniqueName(out[i].Name, taken)
		}
	}
	if out == nil {
		out = []Input{}
	}
	m.Inputs = out
}

func findInput(list []Input, key string) (Input, bool) {
	for _, in := range list {
		if inputKey(in) == key {
			return in, true
		}
	}
	return Input{}, false
}

// fixedValue returns the fixed value a request sends for an input's field.
func fixedValue(r Request, in Input) (any, bool) {
	switch in.In {
	case "query":
		v, ok := r.Query[in.Field]
		return v, ok
	case "body":
		if v, ok := r.Body[in.Field]; ok {
			return v, true
		}
		var cur any = r.Body
		for _, p := range strings.Split(in.Field, ".") {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			if cur, ok = m[p]; !ok {
				return nil, false
			}
		}
		return cur, true
	}
	return nil, false
}

// setFixed sets an input's field to a fixed value in a request: dotted body
// paths set nested keys in JSON bodies.
func setFixed(r *Request, in Input, v any) {
	switch in.In {
	case "query":
		q := make(map[string]any, len(r.Query)+1)
		for k, val := range r.Query {
			q[k] = val
		}
		q[in.Field] = v
		r.Query = q
	case "body":
		r.Body = copyJSONMap(r.Body)
		if r.Body == nil {
			r.Body = map[string]any{}
		}
		if r.BodyType != "json" && r.BodyType != "" {
			r.Body[in.Field] = v
			return
		}
		parts := strings.Split(in.Field, ".")
		cur := r.Body
		for _, p := range parts[:len(parts)-1] {
			next, ok := cur[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				cur[p] = next
			}
			cur = next
		}
		cur[parts[len(parts)-1]] = v
	}
}

// copyJSONMap deep-copies the maps in a JSON-like value, so Merge never
// changes the specs passed in.
func copyJSONMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			v = copyJSONMap(sub)
		}
		out[k] = v
	}
	return out
}
