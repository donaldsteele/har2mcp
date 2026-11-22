// Package spec defines the editable YAML file that sits between analyze and
// generate. analyze writes it, people edit it by hand, and generate reads it.
//
// Rerunning analyze merges into an existing spec (see Merge). Hand edits are
// detected by hashing: when analyze writes a tool it stores FieldHash of each
// user-editable field in Tool.Generated (and of the whole auth block in
// Spec.AuthGenerated). A field whose current hash differs from the stored one
// was edited by hand and is kept.
package spec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// FormatVersion is the value of the top-level "har2mcp" key.
const FormatVersion = 1

// Spec is a whole spec file.
type Spec struct {
	Har2mcp       int     `yaml:"har2mcp"`
	Service       Service `yaml:"service"`
	Auth          Auth    `yaml:"auth"`
	AuthGenerated string  `yaml:"auth_generated,omitempty"`
	Tools         []Tool  `yaml:"tools"`
}

// Service names the device or web app. Name sets the generated server's
// name and its environment variable prefix (see EnvPrefix).
type Service struct {
	Name    string   `yaml:"name"`
	BaseURL string   `yaml:"base_url,omitempty"`
	Hosts   []string `yaml:"hosts,omitempty"`
}

// Auth describes how the generated server logs in and keeps its session.
type Auth struct {
	Mode                string   `yaml:"mode"` // "none" | "http" | "browser"
	Login               *Login   `yaml:"login,omitempty"`
	Session             Session  `yaml:"session,omitempty"`
	ReloginOn           []int    `yaml:"relogin_on,omitempty"`
	ReloginBodyContains string   `yaml:"relogin_body_contains,omitempty"`
	Review              bool     `yaml:"review,omitempty"`
	ReviewNotes         []string `yaml:"review_notes,omitempty"`
}

// Login is the login request (http mode) and the login form (browser mode).
// The request body uses the placeholders {{username}} and {{password}}, which
// the generated server fills from its environment.
type Login struct {
	PageURL string     `yaml:"page_url,omitempty"`
	Request Request    `yaml:"request"`
	Form    *LoginForm `yaml:"form,omitempty"`
}

// LoginForm holds CSS selectors for the login form fields.
type LoginForm struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Submit   string `yaml:"submit"`
}

// Session lists the cookies that carry the session and the tokens the server
// must copy from responses into later requests (CSRF tokens, bearer tokens).
type Session struct {
	Cookies []string    `yaml:"cookies,omitempty"`
	Tokens  []TokenFlow `yaml:"tokens,omitempty"`
}

// TokenFlow says where a token is read from and where it is sent.
type TokenFlow struct {
	Name string   `yaml:"name"`
	From TokenRef `yaml:"from"`
	To   TokenRef `yaml:"to"`
}

// TokenRef is one place a token lives. Exactly one field is set:
// ResponseJSON is a dotted path into a JSON response body; the others name
// a response header, cookie, request header, query key or dotted body path.
type TokenRef struct {
	ResponseJSON   string `yaml:"response_json,omitempty"`
	ResponseHeader string `yaml:"response_header,omitempty"`
	Cookie         string `yaml:"cookie,omitempty"`
	Header         string `yaml:"header,omitempty"`
	Query          string `yaml:"query,omitempty"`
	Body           string `yaml:"body,omitempty"`
}

// Tool is one MCP tool: one operation on the device.
type Tool struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Enabled     bool              `yaml:"enabled"`
	Kind        string            `yaml:"kind"` // "read" | "change" | "destructive"
	Request     Request           `yaml:"request"`
	Inputs      []Input           `yaml:"inputs"`
	File        *FileOp           `yaml:"file,omitempty"`
	Response    Response          `yaml:"response,omitempty"`
	Source      Source            `yaml:"source"`
	Review      bool              `yaml:"review,omitempty"`
	ReviewNotes []string          `yaml:"review_notes,omitempty"`
	Generated   map[string]string `yaml:"generated,omitempty"` // field -> FieldHash at analysis time
}

// Request is the HTTP request a tool sends. Query and Body hold the fixed
// values; inputs are merged into them at call time.
type Request struct {
	Method        string            `yaml:"method"`
	Path          string            `yaml:"path"` // may contain {placeholder} segments
	Query         map[string]any    `yaml:"query,omitempty"`
	BodyType      string            `yaml:"body_type,omitempty"` // "none" | "json" | "form" | "multipart"
	Body          map[string]any    `yaml:"body,omitempty"`
	Headers       map[string]string `yaml:"headers,omitempty"`
	Discriminator string            `yaml:"discriminator,omitempty"`
}

// Input is one tool argument.
//
// Type is string, integer, number, boolean, array or object. In is path,
// query, body or file. Field is, by In: the path placeholder, the query key,
// the dotted body path, or the multipart part.
type Input struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Description string `yaml:"description,omitempty"`
	Required    bool   `yaml:"required,omitempty"`
	In          string `yaml:"in"`
	Field       string `yaml:"field,omitempty"`
	Example     any    `yaml:"example,omitempty"`
}

// FileOp marks an upload or download tool. Part is the multipart part that
// carries the file (uploads only).
type FileOp struct {
	Direction string    `yaml:"direction"` // "upload" | "download"
	Part      string    `yaml:"part,omitempty"`
	Chunked   *Chunking `yaml:"chunked,omitempty"`
}

// Chunking describes a chunked or resumable upload.
type Chunking struct {
	OffsetField string `yaml:"offset_field,omitempty"`
	TotalField  string `yaml:"total_field,omitempty"`
	IndexField  string `yaml:"index_field,omitempty"`
	ChunkSize   int64  `yaml:"chunk_size,omitempty"`
}

// Response describes what a tool's request returns.
type Response struct {
	ContentType string         `yaml:"content_type,omitempty"`
	Schema      map[string]any `yaml:"schema,omitempty"`
	Example     any            `yaml:"example,omitempty"`
}

// Source records where a tool came from. Key is the stable merge key:
// method, normalized path and discriminator value.
type Source struct {
	Key     string   `yaml:"key"`
	Steps   []string `yaml:"steps,omitempty"`
	Samples int      `yaml:"samples"`
	Trigger string   `yaml:"trigger,omitempty"`
}

// EnvPrefix is the prefix of the generated server's environment variables:
// the service name in upper case (TOS_URL, TOS_USER, ...).
func (s *Spec) EnvPrefix() string { return strings.ToUpper(s.Service.Name) }

// FieldHash is the first 8 hex characters of the SHA-256 of v's JSON
// encoding. Empty and nil slices and maps hash alike, at any depth, so the
// hash of a field does not change when a spec is saved and loaded again.
func FieldHash(v any) string {
	b, err := json.Marshal(v)
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var x any
		if err = dec.Decode(&x); err == nil {
			b, err = json.Marshal(normalize(x))
		}
	}
	if err != nil {
		b = []byte(fmt.Sprintf("%#v", v))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:8]
}

// normalize maps empty arrays and objects to nil and drops nil object
// members, so that omitempty round trips do not change a hash.
func normalize(v any) any {
	switch x := v.(type) {
	case []any:
		if len(x) == 0 {
			return nil
		}
		for i := range x {
			x[i] = normalize(x[i])
		}
		return x
	case map[string]any:
		for k, val := range x {
			if n := normalize(val); n == nil {
				delete(x, k)
			} else {
				x[k] = n
			}
		}
		if len(x) == 0 {
			return nil
		}
		return x
	default:
		return v
	}
}
