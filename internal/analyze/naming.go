package analyze

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/donaldsteele/har2mcp/internal/spec"
)

// occurrences records where an operation's requests happened.
type occurrences struct {
	first     map[int]int    // step -> seq of the first request in it
	triggered map[int]bool   // step -> a request in it followed a click
	trigText  map[int]string // step -> text of the first click
	steps     []int          // steps, in order of first request
	outside   bool           // a request happened outside any step
	allTrig   bool           // every request followed a click
	firstTrig string         // text of the first click, anywhere
}

func occurrencesOf(op *operation) occurrences {
	o := occurrences{first: map[int]int{}, triggered: map[int]bool{}, trigText: map[int]string{}, allTrig: true}
	for _, s := range op.samples {
		trig := ""
		if s.triggered() {
			trig = triggerText(s)
			if o.firstTrig == "" {
				o.firstTrig = trig
			}
		} else {
			o.allTrig = false
		}
		if s.step < 0 {
			o.outside = true
			continue
		}
		if _, seen := o.first[s.step]; !seen {
			o.first[s.step] = s.seq
			o.steps = append(o.steps, s.step)
		}
		if s.triggered() {
			o.triggered[s.step] = true
			if o.trigText[s.step] == "" {
				o.trigText[s.step] = trig
			}
		}
	}
	return o
}

// backgroundIn reports whether an operation is background traffic in a
// step: it also happens outside any step or in other steps, and nothing was
// clicked before it in this one (a poll, say).
func (o occurrences) backgroundIn(step int) bool {
	return (o.outside || len(o.steps) > 1) && !o.triggered[step]
}

// background reports whether an operation is background traffic anywhere: it
// happens outside any step or in several steps, and not always after a
// click. Such an operation never takes a step label as a suffix name.
func (o occurrences) background() bool {
	return (o.outside || len(o.steps) > 1) && !o.allTrig
}

func (o occurrences) onlyIn(step int) bool {
	return !o.outside && len(o.steps) == 1 && o.steps[0] == step
}

// nameTools names the tools from the step labels and writes their
// descriptions, kinds and sources.
//
// In each step (in order), the operations that are not background traffic
// in it (seen elsewhere too, and not after a click in this step) compete for
// the step's label. Those seen only in that step go first. The first
// non-read operation gets the label; if all are reads, the first one that
// followed a click does. Other operations in a step are named
// <label>_<action or last path segment>, unless they are background traffic
// somewhere (seen outside any step or in several steps, not always after a
// click: a poll). Background traffic, requests outside any step, and
// requests in a login step are named after their action or last path
// segment alone. User labels claim names first, names are unique, and Go
// keywords get an "_op" suffix.
func nameTools(rec *recording, ds []*draft, au *authResult) {
	occs := make([]occurrences, len(ds))
	stepSet := map[int]bool{}
	for i, d := range ds {
		occs[i] = occurrencesOf(d.op)
		for _, st := range occs[i].steps {
			stepSet[st] = true
		}
	}
	var stepOrder []int
	for st := range stepSet {
		stepOrder = append(stepOrder, st)
	}
	sort.Slice(stepOrder, func(a, b int) bool {
		sa, sb := rec.steps[stepOrder[a]], rec.steps[stepOrder[b]]
		if sa.har != sb.har {
			return sa.har < sb.har
		}
		if !sa.start.Equal(sb.start) {
			return sa.start.Before(sb.start)
		}
		return stepOrder[a] < stepOrder[b]
	})
	labelOK := func(st int) bool { return !au.loginSteps[st] && usableLabel(rec.steps[st].label) }

	primary := make([]int, len(ds))
	secondary := make([]int, len(ds))
	for i := range ds {
		primary[i], secondary[i] = -1, -1
	}
	for _, st := range stepOrder {
		if !labelOK(st) {
			continue
		}
		var cands []int
		for i := range ds {
			if _, in := occs[i].first[st]; in && primary[i] < 0 && !occs[i].backgroundIn(st) {
				cands = append(cands, i)
			}
		}
		sort.SliceStable(cands, func(a, b int) bool { return occs[cands[a]].first[st] < occs[cands[b]].first[st] })
		var pool []int
		for _, i := range cands {
			if occs[i].onlyIn(st) {
				pool = append(pool, i)
			}
		}
		if len(pool) == 0 {
			pool = cands
		}
		pick := -1
		for _, i := range pool {
			if ds[i].kind0 != "read" {
				pick = i
				break
			}
		}
		if pick < 0 {
			for _, i := range pool {
				if occs[i].triggered[st] {
					pick = i
					break
				}
			}
		}
		if pick < 0 && len(pool) > 0 {
			pick = pool[0]
		}
		if pick >= 0 {
			primary[pick] = st
		}
	}
	for i := range ds {
		if primary[i] >= 0 || occs[i].background() {
			continue
		}
		for _, st := range occs[i].steps {
			if labelOK(st) && !occs[i].backgroundIn(st) {
				secondary[i] = st
				break
			}
		}
	}

	base := make([]string, len(ds))
	rank := make([]int, len(ds))
	for i, d := range ds {
		switch {
		case primary[i] >= 0:
			label := rec.steps[primary[i]].label
			base[i] = spec.SanitizeName(label, 64)
			d.tool.Kind = classify(d, label)
		case secondary[i] >= 0:
			base[i] = spec.SanitizeName(rec.steps[secondary[i]].label+" "+nameSuffix(d.op), 64)
			d.tool.Kind = d.kind0
			rank[i] = 1
		default:
			base[i] = spec.SanitizeName(nameSuffix(d.op), 64)
			d.tool.Kind = d.kind0
			rank[i] = 2
		}
		if spec.GoKeywords[base[i]] {
			base[i] += "_op"
		}
	}
	// User labels first, so a background name never takes a label's name.
	taken := map[string]bool{}
	for r := 0; r <= 2; r++ {
		for i := range ds {
			if rank[i] == r {
				ds[i].tool.Name = spec.UniqueName(base[i], taken)
			}
		}
	}

	for i, d := range ds {
		st := primary[i]
		if st < 0 {
			st = secondary[i]
		}
		label, trig := "", ""
		if st >= 0 {
			label, trig = rec.steps[st].label, occs[i].trigText[st]
		} else if occs[i].allTrig && len(occs[i].steps) == 0 {
			trig = occs[i].firstTrig
		}
		t := &d.tool
		t.Description = describe(label, d.op, trig)
		t.Source.Trigger = trig
		seen := map[string]bool{}
		for _, s := range occs[i].steps {
			if l := rec.steps[s].label; l != "" && !seen[l] {
				seen[l] = true
				t.Source.Steps = append(t.Source.Steps, l)
			}
		}
		t.Review = len(d.notes) > 0
		t.ReviewNotes = d.notes
	}
}

// usableLabel reports whether a step label has any letters or digits to
// name a tool with.
func usableLabel(label string) bool {
	return spec.SanitizeName(label, 64) != "unnamed" || strings.Contains(strings.ToLower(label), "unnamed")
}

// nameSuffix names an operation without a label: its discriminator values,
// else its last path segment (with the placeholder after it), else its
// method.
func nameSuffix(op *operation) string {
	if len(op.discVals) > 0 {
		return strings.Join(op.discVals, " ")
	}
	segs := strings.Split(op.path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		s := segs[i]
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "{") {
			name := strings.Trim(s, "{}")
			for j := i - 1; j >= 0; j-- {
				if segs[j] != "" && !strings.HasPrefix(segs[j], "{") {
					return unescapeSeg(segs[j]) + " " + name
				}
			}
			return name
		}
		return unescapeSeg(s)
	}
	return strings.ToLower(op.method)
}

func triggerText(s *sample) string {
	t := s.e.Trigger
	for _, v := range []string{t.Text, t.AriaLabel} {
		if v = strings.Join(strings.Fields(v), " "); v != "" {
			return truncateRunes(v, 60)
		}
	}
	return ""
}

// describe writes a tool description:
// "<Step label>. Calls <METHOD> <path>[ (<field>=<value>)]. Recorded from the
// '<trigger text>' control." Missing parts are left out.
func describe(label string, op *operation, trigger string) string {
	var b strings.Builder
	if l := cleanLabel(label); l != "" {
		b.WriteString(capitalize(l))
		b.WriteString(". ")
	}
	b.WriteString("Calls ")
	b.WriteString(op.method)
	b.WriteString(" ")
	b.WriteString(op.path)
	if len(op.disc) > 0 {
		pairs := make([]string, len(op.disc))
		for i, f := range op.disc {
			pairs[i] = f + "=" + op.discVals[i]
		}
		b.WriteString(" (" + strings.Join(pairs, ", ") + ")")
	}
	b.WriteString(".")
	if trigger != "" {
		b.WriteString(" Recorded from the '" + trigger + "' control.")
	}
	return b.String()
}

func cleanLabel(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.TrimRightFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(".!?:;,…", r)
	})
}

func capitalize(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}
