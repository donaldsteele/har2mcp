package spec

import (
	"strings"
	"testing"
)

// Spec additions from the review of v0.1.0: basic auth, session tokens in
// the URL path, tokens read from text responses or from a request other
// than the login, and chunk indexes that start at 1.
func TestValidateReviewAdditions(t *testing.T) {
	ok := []struct {
		name   string
		mutate func(s *Spec)
	}{
		{"basic auth", func(s *Spec) { s.Auth.Mode = "basic"; s.Auth.Login = nil; s.Auth.ReloginOn = nil }},
		{"path token", func(s *Spec) {
			s.Auth.Session.Tokens = append(s.Auth.Session.Tokens, TokenFlow{Name: "stok", From: TokenRef{ResponseJSON: "result.stok"}, To: TokenRef{Path: "stok"}})
			s.Tools[0].Request.Path = "/cgi-bin/luci/;stok={stok}/admin/status"
		}},
		{"text token from another request", func(s *Spec) {
			s.Auth.Session.Tokens[0].From = TokenRef{ResponseText: `<SID>([0-9a-f]+)</SID>`}
			s.Auth.Session.Tokens[0].Request = &Request{Method: "GET", Path: "/login_sid.lua", Query: map[string]any{"version": "2"}}
		}},
		{"index base", func(s *Spec) { s.Tools[3].File.Chunked = &Chunking{IndexField: "chunk", ChunkSize: 4, IndexBase: 1} }},
	}
	for _, c := range ok {
		t.Run(c.name, func(t *testing.T) {
			s := sampleSpec()
			c.mutate(s)
			if err := s.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}

	bad := []struct {
		name   string
		mutate func(s *Spec)
		want   string
	}{
		{"unknown placeholder", func(s *Spec) { s.Tools[0].Request.Path = "/x/{stok}/y" }, "{stok}"},
		{"bad response_text", func(s *Spec) { s.Auth.Session.Tokens[0].From = TokenRef{ResponseText: `<SID>(`} }, "response_text"},
		{"response_text without a group", func(s *Spec) { s.Auth.Session.Tokens[0].From = TokenRef{ResponseText: `<SID>`} }, "response_text"},
		{"path as a source", func(s *Spec) { s.Auth.Session.Tokens[0].From = TokenRef{Path: "stok"} }, "path"},
		{"response_text as a target", func(s *Spec) { s.Auth.Session.Tokens[0].To = TokenRef{ResponseText: `a(b)`} }, "response_text"},
		{"token request without a path", func(s *Spec) { s.Auth.Session.Tokens[0].Request = &Request{Method: "GET"} }, "request.path"},
		{"negative index base", func(s *Spec) { s.Tools[3].File.Chunked.IndexBase = -1 }, "index_base"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			s := sampleSpec()
			c.mutate(s)
			err := s.Validate()
			if err == nil {
				t.Fatal("Validate accepted an invalid spec")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func inputsByField(tl *Tool) map[string]Input {
	m := map[string]Input{}
	for _, in := range tl.Inputs {
		m[in.In+":"+in.Field] = in
	}
	return m
}

// Inputs merge one by one, keyed on where they go: an edit to one input
// does not freeze the whole list.
func TestMergeInputsOneByOne(t *testing.T) {
	const shareKey = "POST /api.php act=addshare"
	existing := sampleSpec()
	share := toolByKey(existing, shareKey)
	share.Request.Body["quota"] = 0
	share.Inputs = append(share.Inputs, Input{Name: "comment", Type: "string", In: "body", Field: "comment"})
	stampGenerated(existing)
	share = toolByKey(existing, shareKey)
	// Edit one input, as enhance does, and add one by hand.
	share.Inputs[0].Description = "Name of the new share."
	share.Inputs = append(share.Inputs, Input{Name: "mine", Type: "string", In: "query", Field: "mine"})

	fresh := sampleSpec()
	fs := toolByKey(fresh, shareKey)
	fs.Inputs[0].Example = "films"
	fs.Inputs = append(fs.Inputs, Input{Name: "quota", Type: "integer", In: "body", Field: "quota", Example: 100})
	stampGenerated(fresh)

	merged := Merge(existing, fresh)
	if err := merged.Validate(); err != nil {
		t.Fatal(err)
	}
	got := inputsByField(toolByKey(merged, shareKey))
	if got["body:name"].Description != "Name of the new share." {
		t.Errorf("the edited input lost its edit: %+v", got["body:name"])
	}
	if got["body:quota"].Name != "quota" {
		t.Errorf("the new input was not added: %+v", got)
	}
	if got["query:mine"].Name != "mine" {
		t.Errorf("the hand-added input was dropped: %+v", got)
	}
	if _, ok := got["body:comment"]; ok {
		t.Errorf("an unedited input analysis no longer makes was kept: %+v", got)
	}

	// An input the user deleted stays deleted, and its field is sent as a
	// fixed value again.
	existing = Merge(existing, fresh)
	share = toolByKey(existing, shareKey)
	var keep []Input
	for _, in := range share.Inputs {
		if in.Field != "quota" {
			keep = append(keep, in)
		}
	}
	share.Inputs = keep
	again := Merge(existing, fresh)
	tl := toolByKey(again, shareKey)
	if _, ok := inputsByField(tl)["body:quota"]; ok {
		t.Errorf("a deleted input came back: %+v", tl.Inputs)
	}
	if tl.Request.Body["quota"] != 100 || !tl.Review {
		t.Errorf("deleted input: body %v review %v %q", tl.Request.Body, tl.Review, tl.ReviewNotes)
	}
	if err := again.Validate(); err != nil {
		t.Fatal(err)
	}
}

// A spec written before inputs had their own hashes still merges new
// inputs in when an input was edited.
func TestMergeInputsOldSpec(t *testing.T) {
	const shareKey = "POST /api.php act=addshare"
	existing := sampleSpec()
	for i := range existing.Tools {
		for k := range existing.Tools[i].Generated {
			if strings.HasPrefix(k, "input:") {
				delete(existing.Tools[i].Generated, k)
			}
		}
	}
	toolByKey(existing, shareKey).Inputs[0].Description = "Edited."
	fresh := sampleSpec()
	fs := toolByKey(fresh, shareKey)
	fs.Inputs = append(fs.Inputs, Input{Name: "quota", Type: "integer", In: "body", Field: "quota"})
	stampGenerated(fresh)
	got := inputsByField(toolByKey(Merge(existing, fresh), shareKey))
	if got["body:name"].Description != "Edited." || got["body:quota"].Name != "quota" {
		t.Fatalf("inputs = %+v", got)
	}
}
