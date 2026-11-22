// Package har holds the HAR 1.2 types that har2mcp records and analyzes.
//
// The recorder adds its own data only in "_"-prefixed fields, which HAR 1.2
// allows, so other HAR viewers still open the files:
//
//   - log._har2mcp: tool version, start URL, labeled steps, typed inputs and
//     the captured login form (Meta)
//   - entries[]._step and entries[]._trigger: the step a request belongs to
//     and the element that was clicked before it
//   - content._truncated: the body was larger than the recording cap
//
// Chrome DevTools exports load too. Their own extras (_resourceType,
// _webSocketMessages) are kept; other unknown fields are ignored.
package har

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Redacted replaces every secret value that Redact removes.
const Redacted = "REDACTED"

// HAR is the top-level object of a HAR file.
type HAR struct {
	Log Log `json:"log"`
}

// Log is the HAR "log" object.
type Log struct {
	Version string  `json:"version"`
	Creator Creator `json:"creator"`
	Pages   []Page  `json:"pages,omitempty"`
	Entries []Entry `json:"entries"`
	Har2mcp *Meta   `json:"_har2mcp,omitempty"`
}

// Creator names the program that wrote the HAR.
type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Page is a HAR page. har2mcp does not use pages; they are kept so that
// DevTools exports survive a load and save.
type Page struct {
	StartedDateTime time.Time `json:"startedDateTime"`
	ID              string    `json:"id"`
	Title           string    `json:"title"`
}

// Entry is one HTTP request and its response.
type Entry struct {
	StartedDateTime time.Time `json:"startedDateTime"`
	Time            float64   `json:"time"`
	Request         Request   `json:"request"`
	Response        Response  `json:"response"`
	Cache           struct{}  `json:"cache"`
	Timings         Timings   `json:"timings"`

	ResourceType      string      `json:"_resourceType,omitempty"`
	Step              string      `json:"_step,omitempty"`
	Trigger           *Trigger    `json:"_trigger,omitempty"`
	WebSocketMessages []WSMessage `json:"_webSocketMessages,omitempty"`
}

// Request is a HAR request.
type Request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []Cookie    `json:"cookies"`
	Headers     []NameValue `json:"headers"`
	QueryString []NameValue `json:"queryString"`
	PostData    *PostData   `json:"postData,omitempty"`
	HeadersSize int64       `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}

// PostData is a request body. Multipart bodies list their parts in Params.
// Truncated is set when the recorder dropped the text above its size cap;
// Params may still list the fields and parts.
type PostData struct {
	MimeType  string  `json:"mimeType"`
	Text      string  `json:"text"`
	Params    []Param `json:"params,omitempty"`
	Truncated bool    `json:"_truncated,omitempty"`
}

// Param is one posted parameter or multipart part.
type Param struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	FileName    string `json:"fileName,omitempty"`
	ContentType string `json:"contentType,omitempty"`
}

// Response is a HAR response.
type Response struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []Cookie    `json:"cookies"`
	Headers     []NameValue `json:"headers"`
	Content     Content     `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int64       `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}

// Content is a response body. Text is base64 when Encoding is "base64".
// Truncated is set when the recorder dropped a body above its size cap.
type Content struct {
	Size      int64  `json:"size"`
	MimeType  string `json:"mimeType"`
	Text      string `json:"text,omitempty"`
	Encoding  string `json:"encoding,omitempty"`
	Truncated bool   `json:"_truncated,omitempty"`
}

// Cookie is a request or response cookie.
type Cookie struct {
	Name     string     `json:"name"`
	Value    string     `json:"value"`
	Path     string     `json:"path,omitempty"`
	Domain   string     `json:"domain,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"`
	HTTPOnly bool       `json:"httpOnly,omitempty"`
	Secure   bool       `json:"secure,omitempty"`
}

// NameValue is a header or query string pair.
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Timings holds the request phases HAR 1.2 requires, in milliseconds.
type Timings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// WSMessage is a WebSocket frame, in Chrome's _webSocketMessages format.
type WSMessage struct {
	Type   string  `json:"type"`
	Time   float64 `json:"time"`
	Opcode int     `json:"opcode"`
	Data   string  `json:"data"`
}

// Meta is the _har2mcp block the recorder writes at the top of the log.
type Meta struct {
	Version  string        `json:"version"`
	StartURL string        `json:"startUrl"`
	Steps    []Step        `json:"steps"`
	Login    *LoginCapture `json:"login,omitempty"`
}

// Step is one step the user labeled in the recorder overlay.
type Step struct {
	Name   string       `json:"name"`
	Start  time.Time    `json:"start"`
	End    time.Time    `json:"end"`
	Inputs []TypedInput `json:"inputs,omitempty"`
}

// TypedInput is a form value the user typed during a step.
type TypedInput struct {
	Label    string `json:"label,omitempty"`
	Name     string `json:"name,omitempty"`
	Selector string `json:"selector,omitempty"`
	Type     string `json:"type,omitempty"`
	Value    string `json:"value"`
}

// Trigger describes the element clicked just before a request.
type Trigger struct {
	Text      string `json:"text,omitempty"`
	AriaLabel string `json:"ariaLabel,omitempty"`
	Role      string `json:"role,omitempty"`
	Selector  string `json:"selector,omitempty"`
}

// LoginCapture is the login form the recorder saw submitted: the selectors
// for a browser-mode login and the typed values analysis compares against.
type LoginCapture struct {
	PageURL          string `json:"pageUrl,omitempty"`
	UsernameSelector string `json:"usernameSelector,omitempty"`
	PasswordSelector string `json:"passwordSelector,omitempty"`
	SubmitSelector   string `json:"submitSelector,omitempty"`
	Username         string `json:"username,omitempty"`
	Password         string `json:"password,omitempty"`
}

// Bytes returns the decoded body: Text itself, or Text decoded from base64
// when Encoding is "base64" (padded or not).
func (c Content) Bytes() ([]byte, error) {
	switch strings.ToLower(c.Encoding) {
	case "":
		return []byte(c.Text), nil
	case "base64":
		s := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, c.Text)
		if b, err := base64.StdEncoding.DecodeString(s); err == nil {
			return b, nil
		}
		b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return nil, fmt.Errorf("har: content is not valid base64: %w", err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("har: unsupported content encoding %q", c.Encoding)
	}
}

// Header returns the value of the first request header named name, compared
// case-insensitively, or "" when there is none.
func (r Request) Header(name string) string { return header(r.Headers, name) }

// Header returns the value of the first response header named name, compared
// case-insensitively, or "" when there is none.
func (r Response) Header(name string) string { return header(r.Headers, name) }

func header(h []NameValue, name string) string {
	for _, nv := range h {
		if strings.EqualFold(nv.Name, name) {
			return nv.Value
		}
	}
	return ""
}

// The MarshalJSON methods below write the arrays HAR 1.2 requires as [] when
// they are nil, so strict HAR readers accept the files.

// MarshalJSON writes entries as [] when there are none.
func (l Log) MarshalJSON() ([]byte, error) {
	type plain Log
	p := plain(l)
	if p.Entries == nil {
		p.Entries = []Entry{}
	}
	return marshal(p)
}

// MarshalJSON adds the pageTimings object HAR 1.2 requires on a page.
func (p Page) MarshalJSON() ([]byte, error) {
	type plain Page
	return marshal(struct {
		plain
		PageTimings struct{} `json:"pageTimings"`
	}{plain: plain(p)})
}

// MarshalJSON writes cookies, headers and queryString as [] when empty.
func (r Request) MarshalJSON() ([]byte, error) {
	type plain Request
	p := plain(r)
	if p.Cookies == nil {
		p.Cookies = []Cookie{}
	}
	if p.Headers == nil {
		p.Headers = []NameValue{}
	}
	if p.QueryString == nil {
		p.QueryString = []NameValue{}
	}
	return marshal(p)
}

// MarshalJSON writes cookies and headers as [] when empty.
func (r Response) MarshalJSON() ([]byte, error) {
	type plain Response
	p := plain(r)
	if p.Cookies == nil {
		p.Cookies = []Cookie{}
	}
	if p.Headers == nil {
		p.Headers = []NameValue{}
	}
	return marshal(p)
}

// MarshalJSON writes steps as [] when there are none.
func (m Meta) MarshalJSON() ([]byte, error) {
	type plain Meta
	p := plain(m)
	if p.Steps == nil {
		p.Steps = []Step{}
	}
	return marshal(p)
}

// UnmarshalJSON reads a cookie, ignoring an expiry that is not a valid
// timestamp (null, "", "Infinity" and similar appear in real exports).
func (c *Cookie) UnmarshalJSON(b []byte) error {
	type plain Cookie
	var aux struct {
		plain
		Expires json.RawMessage `json:"expires"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*c = Cookie(aux.plain)
	c.Expires = nil
	var s string
	if len(aux.Expires) > 0 && json.Unmarshal(aux.Expires, &s) == nil && s != "" {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			c.Expires = &t
		}
	}
	return nil
}

// marshal is json.Marshal without HTML escaping, so URLs keep their "&".
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
