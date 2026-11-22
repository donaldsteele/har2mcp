package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/donaldsteele/har2mcp/internal/spec"
)

func TestQuoteArgFor(t *testing.T) {
	for _, c := range []struct{ goos, in, want string }{
		{"linux", "nas.spec.yaml", "nas.spec.yaml"},
		{"linux", "/home/jane/My Devices/nas-mcp", "'/home/jane/My Devices/nas-mcp'"},
		{"darwin", "it's.har", `'it'\''s.har'`},
		{"windows", `C:\Users\jane\nas-mcp`, `C:\Users\jane\nas-mcp`},
		{"windows", `C:\Users\Jane Doe\nas-mcp`, `"C:\Users\Jane Doe\nas-mcp"`},
		{"windows", "a&b", `"a&b"`},
		{"windows", "NAS_URL=http://192.168.1.10", "NAS_URL=http://192.168.1.10"},
	} {
		if got := quoteArgFor(c.goos, c.in); got != c.want {
			t.Errorf("quoteArgFor(%s, %q) = %s, want %s", c.goos, c.in, got, c.want)
		}
	}
}

// The printed build and register commands paste correctly into each OS's
// shell, even when the paths have spaces.
func TestPrintNextStepsQuotes(t *testing.T) {
	s := &spec.Spec{Service: spec.Service{Name: "nas", BaseURL: "http://192.168.1.10"}, Auth: spec.Auth{Mode: "http"}}
	var win bytes.Buffer
	printNextSteps(&win, "windows", s, `C:\Users\Jane Doe\nas-mcp`, "nas-mcp.exe", `C:\Users\Jane Doe\nas-mcp\nas-mcp.exe`)
	for _, want := range []string{`cd "C:\Users\Jane Doe\nas-mcp"`, `-- "C:\Users\Jane Doe\nas-mcp\nas-mcp.exe"`, "--env NAS_PASSWORD=your-password ", "--env NAS_URL=http://192.168.1.10 "} {
		if !strings.Contains(win.String(), want) {
			t.Errorf("windows output lacks %q:\n%s", want, win.String())
		}
	}
	if strings.Contains(win.String(), "'") {
		t.Errorf("windows output uses single quotes:\n%s", win.String())
	}
	var unix bytes.Buffer
	printNextSteps(&unix, "darwin", s, "/Users/jane/My Devices/nas-mcp", "nas-mcp", "/Users/jane/My Devices/nas-mcp/nas-mcp")
	for _, want := range []string{"cd '/Users/jane/My Devices/nas-mcp'", "-- '/Users/jane/My Devices/nas-mcp/nas-mcp'", "--env NAS_PASSWORD='your-password'"} {
		if !strings.Contains(unix.String(), want) {
			t.Errorf("unix output lacks %q:\n%s", want, unix.String())
		}
	}
}

// analyze says when the API answered somewhere other than the recorded
// address.
func TestAnalyzeSummaryNotesBaseURL(t *testing.T) {
	s := &spec.Spec{Service: spec.Service{Name: "hub", BaseURL: "https://hub.local:5443"}, Auth: spec.Auth{Mode: "http"}}
	var b bytes.Buffer
	printAnalyzeSummary(&b, "hub.spec.yaml", s, nil, "http://hub.local:8181")
	if !strings.Contains(b.String(), "https://hub.local:5443") || !strings.Contains(b.String(), "http://hub.local:8181") {
		t.Errorf("summary = %s", b.String())
	}
	b.Reset()
	printAnalyzeSummary(&b, "hub.spec.yaml", s, nil, "https://hub.local:5443")
	if strings.Contains(b.String(), "Note:") {
		t.Errorf("unexpected note: %s", b.String())
	}
}
