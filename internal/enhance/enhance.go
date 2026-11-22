// Package enhance asks Claude for better tool names and descriptions.
//
// It is the only part of har2mcp that sends anything off the machine, and it
// runs only when the user runs 'har2mcp enhance'. What it sends is built by
// Payload: tool names, kinds, request shapes, step labels and short redacted
// response examples. It never sends the auth block, request headers, fixed
// request values, typed input examples or the HAR. Apply writes back only
// tool names, tool descriptions and input descriptions.
package enhance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// DefaultModel is the Claude model enhance uses unless told otherwise.
const DefaultModel = "claude-opus-5-5"

// maxExampleChars caps each response example in the payload.
const maxExampleChars = 2000

// Client sends one prompt to Claude and returns the text of the reply.
type Client interface {
	Complete(ctx context.Context, system, prompt string) (string, error)
}

// Options control Enhance.
type Options struct {
	Model  string    // shown in the dry run; "" means DefaultModel
	DryRun bool      // print what would be sent and send nothing
	Out    io.Writer // dry-run output and the change summary; nil means os.Stdout for dry runs, nothing otherwise
}

// SystemPrompt is the system prompt sent with every enhance request.
const SystemPrompt = `You name and describe MCP tools for a device's web API. The tools were recorded from a person using the device's web UI, so the current names come from their step labels or from internal API action names.

You get JSON describing the tools. For each one, write:
- name: a concise snake_case name in verb_noun form, such as list_disks, create_share or delete_user. Use lower case letters, digits and underscores, start with a letter, use at most 64 characters, and keep every name unique.
- description: one sentence saying what the tool does on the device, in plain words. Say so when a tool deletes data, reboots or otherwise destroys or interrupts something.
- inputs: a short description of each input, keyed by the input's name exactly as given.

Keep each tool's key exactly as given, and do not add or drop tools. Reply with JSON only, no prose and no code fences, in this shape:
{"tools":[{"key":"...","name":"...","description":"...","inputs":{"<input name>":"<description>"}}]}`

// payload is the JSON sent to Claude.
type payload struct {
	Service string        `json:"service"`
	Tools   []payloadTool `json:"tools"`
}

type payloadTool struct {
	Key             string         `json:"key"`
	Name            string         `json:"name"`
	Description     string         `json:"description,omitempty"`
	Kind            string         `json:"kind"`
	Method          string         `json:"method"`
	Path            string         `json:"path"`
	Discriminator   string         `json:"discriminator,omitempty"`
	Steps           []string       `json:"steps,omitempty"`
	Trigger         string         `json:"trigger,omitempty"`
	File            string         `json:"file,omitempty"`
	Inputs          []payloadInput `json:"inputs,omitempty"`
	ResponseExample string         `json:"response_example,omitempty"`
}

type payloadInput struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	In          string `json:"in"`
	Field       string `json:"field,omitempty"`
	Description string `json:"description,omitempty"`
}

// toolKey identifies a tool in the payload and the reply: its merge key, or
// its name when a hand-written tool has none.
func toolKey(t *spec.Tool) string {
	if t.Source.Key != "" {
		return t.Source.Key
	}
	return "name:" + t.Name
}

// Payload returns the JSON that Enhance sends to Claude, for each tool: its
// key, name, description, kind, method, path, discriminator value, step
// labels, trigger text, inputs (name, type, where they go) and a redacted
// response example of at most 2000 characters. It leaves out the auth
// block, request headers, fixed request values, input examples, the service
// address and the hosts.
func Payload(s *spec.Spec) (string, error) {
	p := payload{Service: s.Service.Name, Tools: []payloadTool{}}
	for i := range s.Tools {
		t := &s.Tools[i]
		pt := payloadTool{
			Key:         toolKey(t),
			Name:        t.Name,
			Description: t.Description,
			Kind:        t.Kind,
			Method:      t.Request.Method,
			Path:        t.Request.Path,
			Steps:       t.Source.Steps,
			Trigger:     t.Source.Trigger,
		}
		if d := t.Request.Discriminator; d != "" {
			if v, ok := discriminatorValue(t.Request, d); ok {
				pt.Discriminator = d + "=" + v
			}
		}
		if t.File != nil {
			pt.File = t.File.Direction
		}
		for _, in := range t.Inputs {
			pt.Inputs = append(pt.Inputs, payloadInput{Name: in.Name, Type: in.Type, In: in.In, Field: in.Field, Description: in.Description})
		}
		if t.Response.Example != nil {
			ex, err := exampleText(t.Response.Example)
			if err != nil {
				return "", fmt.Errorf("tool %s: response example: %w", t.Name, err)
			}
			pt.ResponseExample = ex
		}
		p.Tools = append(p.Tools, pt)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

// discriminatorValue is the fixed value of the discriminator field, from the
// body (a dotted path) or the query.
func discriminatorValue(r spec.Request, field string) (string, bool) {
	var v any = r.Body
	for _, part := range strings.Split(field, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			v = nil
			break
		}
		v = m[part]
	}
	if v == nil {
		v = r.Query[field]
	}
	switch v.(type) {
	case string, bool, int, int64, float64, json.Number:
		return fmt.Sprint(v), true
	}
	return "", false
}

// secretKeyRE matches JSON keys whose values must not leave the machine.
var secretKeyRE = regexp.MustCompile(`(?i)(pass(wd|word)?|pwd|secret|token|csrf|xsrf|session|sess_?id|^sid$|api_?key|auth|cookie|credential|private)`)

// exampleText redacts a response example and truncates its JSON to
// maxExampleChars characters.
func exampleText(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(redactValue(x)); err != nil {
		return "", err
	}
	s := strings.TrimRight(buf.String(), "\n")
	if utf8.RuneCountInString(s) > maxExampleChars {
		const more = " ...(truncated)"
		r := []rune(s)
		s = string(r[:maxExampleChars-len(more)]) + more
	}
	return s, nil
}

func redactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if secretKeyRE.MatchString(k) {
				if _, nested := e.(map[string]any); !nested {
					out[k] = har.Redacted
					continue
				}
			}
			out[k] = redactValue(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redactValue(e)
		}
		return out
	}
	return v
}

// reply is the JSON Claude returns.
type reply struct {
	Tools []struct {
		Key         string            `json:"key"`
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Inputs      map[string]string `json:"inputs"`
	} `json:"tools"`
}

var toolNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Apply writes Claude's reply into s. The reply is JSON (code fences and
// text around it are ignored) shaped like
//
//	{"tools":[{"key":"...","name":"...","description":"...","inputs":{"<input>":"<description>"}}]}
//
// Only tool names, tool descriptions and input descriptions change. Empty
// values and unknown keys or inputs are skipped. An invalid or duplicate
// name, a key listed twice, a reply that matches no tool, or a result that
// fails validation is an error, and then s is left unchanged.
func Apply(s *spec.Spec, response string) error {
	raw, err := extractJSON(response)
	if err != nil {
		return err
	}
	var r reply
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return fmt.Errorf("the reply is not the expected JSON: %w", err)
	}

	byKey := map[string]int{}
	for i := range s.Tools {
		k := toolKey(&s.Tools[i])
		if _, dup := byKey[k]; dup {
			return fmt.Errorf("the spec has two tools with the key %q; fix the spec first", k)
		}
		byKey[k] = i
	}
	work := make([]spec.Tool, len(s.Tools))
	for i, t := range s.Tools {
		t.Inputs = slices.Clone(t.Inputs)
		work[i] = t
	}
	seen := map[string]bool{}
	matched := 0
	for _, rt := range r.Tools {
		if seen[rt.Key] {
			return fmt.Errorf("the reply lists the key %q twice", rt.Key)
		}
		seen[rt.Key] = true
		i, ok := byKey[rt.Key]
		if !ok {
			continue
		}
		matched++
		t := &work[i]
		if name := strings.TrimSpace(rt.Name); name != "" {
			if !toolNameRE.MatchString(name) {
				return fmt.Errorf("the reply's name %q for %s is not a valid tool name (lower case letters, digits and _, starting with a letter, at most 64 characters)", name, rt.Key)
			}
			t.Name = name
		}
		if d := strings.TrimSpace(rt.Description); d != "" {
			t.Description = d
		}
		for j := range t.Inputs {
			if d := strings.TrimSpace(rt.Inputs[t.Inputs[j].Name]); d != "" {
				t.Inputs[j].Description = d
			}
		}
	}
	if matched == 0 {
		return errors.New("the reply matched none of the spec's tools")
	}
	names := map[string]string{}
	for i := range work {
		if other, dup := names[work[i].Name]; dup {
			return fmt.Errorf("the reply gives two tools the name %q (%s and %s)", work[i].Name, other, toolKey(&work[i]))
		}
		names[work[i].Name] = toolKey(&work[i])
	}
	check := *s
	check.Tools = work
	if err := check.Validate(); err != nil {
		return fmt.Errorf("the reply would make the spec invalid:\n%w", err)
	}
	s.Tools = work
	return nil
}

// extractJSON finds the JSON object in a reply that may wrap it in a code
// fence or text.
func extractJSON(s string) (string, error) {
	start, end := strings.Index(s, "{"), strings.LastIndex(s, "}")
	if start < 0 || end < start {
		return "", fmt.Errorf("the reply contains no JSON object: %q", truncate(s, 200))
	}
	return s[start : end+1], nil
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

// userPrompt is the user message: the payload with a short lead-in.
func userPrompt(p string) string {
	return "Improve the names and descriptions of these tools.\n\n" + p
}

// Enhance sends the spec's tools to Claude and applies the reply to s. With
// opts.DryRun it prints exactly what would be sent and sends nothing.
func Enhance(ctx context.Context, s *spec.Spec, c Client, opts Options) error {
	p, err := Payload(s)
	if err != nil {
		return err
	}
	prompt := userPrompt(p)
	model := opts.Model
	if model == "" {
		model = DefaultModel
	}
	if opts.DryRun {
		out := opts.Out
		if out == nil {
			out = os.Stdout
		}
		_, err := fmt.Fprintf(out, "Dry run: nothing was sent. 'har2mcp enhance' would send this to the Claude API (model %s):\n\n--- system prompt ---\n%s\n\n--- user message ---\n%s\n", model, SystemPrompt, prompt)
		return err
	}
	if c == nil {
		return errors.New("enhance: no Claude client")
	}
	before := make([]spec.Tool, len(s.Tools))
	copy(before, s.Tools)
	resp, err := c.Complete(ctx, SystemPrompt, prompt)
	if err != nil {
		return err
	}
	if err := Apply(s, resp); err != nil {
		return err
	}
	if opts.Out != nil {
		summarize(opts.Out, before, s.Tools)
	}
	return nil
}

func summarize(w io.Writer, before, after []spec.Tool) {
	renamed, described := 0, 0
	for i := range after {
		if after[i].Name != before[i].Name {
			renamed++
			fmt.Fprintf(w, "  %s -> %s\n", before[i].Name, after[i].Name)
		}
		if after[i].Description != before[i].Description {
			described++
		}
	}
	fmt.Fprintf(w, "Renamed %d and redescribed %d of %d tools.\n", renamed, described, len(after))
}
