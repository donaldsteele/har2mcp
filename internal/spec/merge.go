package spec

// editableFields are the tool fields a person may change by hand. Merge keeps
// a field when its hash no longer matches Tool.Generated, and takes the fresh
// value otherwise. Everything else on a tool (request, response, source,
// file, review flags) always comes from the fresh analysis.
var editableFields = []string{"name", "description", "enabled", "kind", "inputs"}

// GeneratedHashes returns the Tool.Generated map for t: FieldHash of each
// user-editable field (name, description, enabled, kind, inputs), and of
// each input on its own under "input:<in>:<field>", so Merge can tell which
// inputs were edited.
func GeneratedHashes(t *Tool) map[string]string {
	m := make(map[string]string, len(editableFields)+len(t.Inputs))
	for _, f := range editableFields {
		m[f] = FieldHash(fieldValue(t, f))
	}
	for _, in := range t.Inputs {
		m[inputHashPrefix+inputKey(in)] = FieldHash(in)
	}
	return m
}

func fieldValue(t *Tool, field string) any {
	switch field {
	case "name":
		return t.Name
	case "description":
		return t.Description
	case "enabled":
		return t.Enabled
	case "kind":
		return t.Kind
	case "inputs":
		return t.Inputs
	}
	panic("spec: unknown editable field " + field)
}

// edited reports whether a field of an existing tool was changed by hand. A
// field with no recorded hash counts as edited, so a hand-written spec is
// never overwritten.
func edited(t *Tool, field string) bool {
	h, ok := t.Generated[field]
	return !ok || FieldHash(fieldValue(t, field)) != h
}

// Merge combines an existing spec (possibly hand-edited) with a freshly
// analyzed one and returns the result. Neither argument is modified.
//
//   - Tools are matched on Source.Key. For name, description, enabled and
//     kind, a field edited by hand is kept; otherwise the fresh value is
//     taken. Inputs merge one by one, keyed on where each goes (see
//     mergeInputs). Request, response, source, file and review flags come
//     from the fresh tool, and Generated is recomputed from the fresh values.
//   - Tools only in the existing spec are kept; tools only in the fresh spec
//     are appended. Existing tools keep their order.
//   - Names stay unique: a name the user chose wins, and a colliding name
//     from analysis gets a _2, _3 ... suffix.
//   - The auth block follows the same rule as one unit, using AuthGenerated.
//   - The service name and base URL are kept from the existing spec (the
//     generated server's environment variables depend on the name); hosts are
//     the union of both.
func Merge(existing, fresh *Spec) *Spec {
	switch {
	case existing == nil && fresh == nil:
		return nil
	case existing == nil:
		return copySpec(fresh)
	case fresh == nil:
		return copySpec(existing)
	}

	out := &Spec{Har2mcp: FormatVersion}

	out.Service = existing.Service
	if out.Service.Name == "" {
		out.Service.Name = fresh.Service.Name
	}
	if out.Service.BaseURL == "" {
		out.Service.BaseURL = fresh.Service.BaseURL
	}
	out.Service.Hosts = union(existing.Service.Hosts, fresh.Service.Hosts)

	if existing.AuthGenerated == "" || FieldHash(existing.Auth) != existing.AuthGenerated {
		out.Auth = existing.Auth
	} else {
		out.Auth = fresh.Auth
	}
	out.AuthGenerated = FieldHash(fresh.Auth)

	freshByKey := map[string]*Tool{}
	for i := range fresh.Tools {
		t := &fresh.Tools[i]
		if t.Source.Key != "" {
			if _, dup := freshByKey[t.Source.Key]; !dup {
				freshByKey[t.Source.Key] = t
			}
		}
	}

	// pinned marks tools whose name belongs to the user: a hand-edited name,
	// or a tool analysis no longer produces.
	var pinned []bool
	used := map[string]bool{}
	for i := range existing.Tools {
		old := &existing.Tools[i]
		nt, ok := freshByKey[old.Source.Key]
		if !ok || used[old.Source.Key] {
			out.Tools = append(out.Tools, copyTool(old))
			pinned = append(pinned, true)
			continue
		}
		used[old.Source.Key] = true
		m := copyTool(nt)
		if edited(old, "name") {
			m.Name = old.Name
		}
		if edited(old, "description") {
			m.Description = old.Description
		}
		if edited(old, "enabled") {
			m.Enabled = old.Enabled
		}
		if edited(old, "kind") {
			m.Kind = old.Kind
		}
		mergeInputs(old, nt, &m)
		m.Generated = GeneratedHashes(nt)
		out.Tools = append(out.Tools, m)
		pinned = append(pinned, edited(old, "name"))
	}
	for i := range fresh.Tools {
		nt := &fresh.Tools[i]
		if nt.Source.Key != "" && used[nt.Source.Key] {
			continue
		}
		if nt.Source.Key != "" {
			used[nt.Source.Key] = true
		}
		m := copyTool(nt)
		m.Generated = GeneratedHashes(nt)
		out.Tools = append(out.Tools, m)
		pinned = append(pinned, false)
	}

	// User-owned names first, then the rest, so analysis never steals a name.
	taken := map[string]bool{}
	for _, pass := range []bool{true, false} {
		for i := range out.Tools {
			if pinned[i] == pass {
				out.Tools[i].Name = UniqueName(out.Tools[i].Name, taken)
			}
		}
	}
	return out
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

func copySpec(s *Spec) *Spec {
	out := *s
	out.Service.Hosts = append([]string(nil), s.Service.Hosts...)
	out.Tools = make([]Tool, len(s.Tools))
	for i := range s.Tools {
		out.Tools[i] = copyTool(&s.Tools[i])
	}
	return &out
}

// copyTool copies a tool deeply enough that Merge's changes (names, inputs,
// Generated) never reach the specs passed in.
func copyTool(t *Tool) Tool {
	c := *t
	c.Inputs = append([]Input(nil), t.Inputs...)
	c.ReviewNotes = append([]string(nil), t.ReviewNotes...)
	if t.Generated != nil {
		c.Generated = make(map[string]string, len(t.Generated))
		for k, v := range t.Generated {
			c.Generated[k] = v
		}
	}
	return c
}
