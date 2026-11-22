package inspect

import (
	"bytes"
	"strings"
	"testing"

	"github.com/donaldsteele/har2mcp/internal/spec"
)

// The summary shows Basic auth, path tokens, tokens read from another
// request, and a chunk index that starts at 1.
func TestInspectSpecReviewAdditions(t *testing.T) {
	s := &spec.Spec{
		Har2mcp: spec.FormatVersion,
		Service: spec.Service{Name: "router"},
		Auth: spec.Auth{Mode: "basic", Session: spec.Session{Tokens: []spec.TokenFlow{
			{Name: "stok", From: spec.TokenRef{ResponseText: `<SID>([0-9a-f]+)</SID>`}, To: spec.TokenRef{Path: "stok"},
				Request: &spec.Request{Method: "GET", Path: "/api/session"}},
		}}},
		Tools: []spec.Tool{
			{Name: "status", Kind: "read", Enabled: true, Request: spec.Request{Method: "GET", Path: "/cgi-bin/luci/;stok={stok}/admin/status"}},
			{Name: "upload", Kind: "change", Enabled: true, Request: spec.Request{Method: "POST", Path: "/up", BodyType: "multipart"},
				File:   &spec.FileOp{Direction: "upload", Part: "file", Chunked: &spec.Chunking{IndexField: "n", ChunkSize: 4, IndexBase: 1}},
				Inputs: []spec.Input{{Name: "local_path", Type: "string", Required: true, In: "file", Field: "file"}}},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Spec(&buf, s); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Auth: basic", "HTTP Basic", "response_text", "of GET /api/session", "-> path stok", "first index 1", "ROUTER_USER"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
}
