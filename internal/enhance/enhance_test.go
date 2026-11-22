package enhance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/donaldsteele/har2mcp/internal/spec"
)

func testSpec() *spec.Spec {
	return &spec.Spec{
		Har2mcp: spec.FormatVersion,
		Service: spec.Service{Name: "nas", BaseURL: "http://192.168.1.10", Hosts: []string{"192.168.1.10"}},
		Auth: spec.Auth{
			Mode: "http",
			Login: &spec.Login{
				PageURL: "http://192.168.1.10/",
				Request: spec.Request{Method: "POST", Path: "/api/login", BodyType: "json",
					Body: map[string]any{"username": "{{username}}", "password": "{{password}}"}},
			},
			Session: spec.Session{
				Cookies: []string{"NASSESSID"},
				Tokens:  []spec.TokenFlow{{Name: "csrf", From: spec.TokenRef{ResponseJSON: "data.token"}, To: spec.TokenRef{Header: "X-Csrf-Token"}}},
			},
			ReloginOn: []int{401, 403},
		},
		Tools: []spec.Tool{
			{
				Name: "list_disks", Description: "List disks. Calls POST /api.php (act=getdisklist).", Enabled: true, Kind: "read",
				Request: spec.Request{Method: "POST", Path: "/api.php", BodyType: "json", Body: map[string]any{"act": "getdisklist", "lang": "secret-fixed-value"},
					Headers: map[string]string{"X-Requested-With": "XMLHttpRequest-header-value"}, Discriminator: "act"},
				Inputs: []spec.Input{},
				Response: spec.Response{ContentType: "application/json", Example: map[string]any{
					"ok": true, "data": []any{map[string]any{"id": "sda", "model": strings.Repeat("WD Red ", 600)}}, "session_token": "abc123xyz"}},
				Source: spec.Source{Key: "POST /api.php act=getdisklist", Steps: []string{"list disks"}, Samples: 2, Trigger: "Disks"},
			},
			{
				Name: "addshare", Description: "Add share.", Enabled: true, Kind: "change",
				Request: spec.Request{Method: "POST", Path: "/api.php", BodyType: "json", Body: map[string]any{"act": "addshare"}, Discriminator: "act"},
				Inputs:  []spec.Input{{Name: "name", Type: "string", Required: true, In: "body", Field: "name", Example: "typed-example-value"}},
				Source:  spec.Source{Key: "POST /api.php act=addshare", Steps: []string{"add share"}, Samples: 1},
			},
		},
	}
}

func TestPayloadExcludesAuth(t *testing.T) {
	p, err := Payload(testSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"auth", "login", "password", "NASSESSID", "X-Csrf-Token", "data.token", "XMLHttpRequest-header-value",
		"192.168.1.10", "secret-fixed-value", "typed-example-value", "abc123xyz"} {
		if strings.Contains(p, bad) {
			t.Errorf("payload contains %q:\n%s", bad, p)
		}
	}
	var got struct {
		Service string `json:"service"`
		Tools   []struct {
			Key, Name, Kind, Method, Path, Discriminator, Trigger string
			Steps                                                 []string
			Inputs                                                []struct{ Name, Type string }
			ResponseExample                                       string `json:"response_example"`
		} `json:"tools"`
	}
	if err := json.Unmarshal([]byte(p), &got); err != nil {
		t.Fatalf("payload is not JSON: %v\n%s", err, p)
	}
	if got.Service != "nas" || len(got.Tools) != 2 {
		t.Fatalf("payload = %+v", got)
	}
	t0 := got.Tools[0]
	if t0.Key != "POST /api.php act=getdisklist" || t0.Name != "list_disks" || t0.Kind != "read" || t0.Method != "POST" ||
		t0.Path != "/api.php" || t0.Discriminator != "act=getdisklist" || t0.Trigger != "Disks" || !reflect.DeepEqual(t0.Steps, []string{"list disks"}) {
		t.Errorf("tool 0 = %+v", t0)
	}
	if n := len([]rune(t0.ResponseExample)); n > 2000 || n < 100 {
		t.Errorf("response example has %d characters, want 100..2000", n)
	}
	if !strings.Contains(t0.ResponseExample, "sda") {
		t.Errorf("response example = %q", t0.ResponseExample)
	}
	if in := got.Tools[1].Inputs; len(in) != 1 || in[0].Name != "name" || in[0].Type != "string" {
		t.Errorf("tool 1 inputs = %+v", in)
	}
}

func TestApplyOnlyTextFields(t *testing.T) {
	s := testSpec()
	before := testSpec()
	resp := `{"tools":[
		{"key":"POST /api.php act=addshare","name":"create_share","description":"Create a shared folder on the NAS.","inputs":{"name":"Name of the new share."}},
		{"key":"no such key","name":"ghost_tool","description":"x"}
	]}`
	if err := Apply(s, resp); err != nil {
		t.Fatal(err)
	}
	got := s.Tools[1]
	if got.Name != "create_share" || got.Description != "Create a shared folder on the NAS." || got.Inputs[0].Description != "Name of the new share." {
		t.Errorf("tool = %+v", got)
	}
	if !reflect.DeepEqual(got.Request, before.Tools[1].Request) || got.Kind != before.Tools[1].Kind || got.Enabled != before.Tools[1].Enabled ||
		!reflect.DeepEqual(got.Source, before.Tools[1].Source) || got.Inputs[0].Field != "name" {
		t.Errorf("Apply changed more than text fields: %+v", got)
	}
	if !reflect.DeepEqual(s.Tools[0], before.Tools[0]) || !reflect.DeepEqual(s.Auth, before.Auth) {
		t.Error("Apply changed an unmentioned tool or the auth block")
	}

	for name, bad := range map[string]string{
		"duplicate name":    `{"tools":[{"key":"POST /api.php act=addshare","name":"list_disks"}]}`,
		"invalid name":      `{"tools":[{"key":"POST /api.php act=addshare","name":"Create Share!"}]}`,
		"duplicate key":     `{"tools":[{"key":"POST /api.php act=addshare","name":"a_b"},{"key":"POST /api.php act=addshare","name":"c_d"}]}`,
		"not json":          `I could not do that.`,
		"no matching tools": `{"tools":[{"key":"nope","name":"x_y"}]}`,
	} {
		s := testSpec()
		s.Tools[1].Name = "create_share_before"
		snapshot := testSpec()
		snapshot.Tools[1].Name = "create_share_before"
		if err := Apply(s, bad); err == nil {
			t.Errorf("%s: no error", name)
		}
		if !reflect.DeepEqual(s, snapshot) {
			t.Errorf("%s: spec changed on error", name)
		}
	}
}

func TestApplyAcceptsFencedJSON(t *testing.T) {
	s := testSpec()
	resp := "Here you go:\n```json\n{\"tools\":[{\"key\":\"POST /api.php act=getdisklist\",\"name\":\"list_disks\",\"description\":\"List every disk with its model, size and health.\"}]}\n```\n"
	if err := Apply(s, resp); err != nil {
		t.Fatal(err)
	}
	if s.Tools[0].Description != "List every disk with its model, size and health." {
		t.Errorf("description = %q", s.Tools[0].Description)
	}
}

type fakeClient struct {
	resp           string
	err            error
	called         bool
	system, prompt string
}

func (f *fakeClient) Complete(ctx context.Context, system, prompt string) (string, error) {
	f.called = true
	f.system, f.prompt = system, prompt
	return f.resp, f.err
}

func TestEnhanceDryRunSendsNothing(t *testing.T) {
	c := &fakeClient{err: errors.New("must not be called")}
	var out bytes.Buffer
	s := testSpec()
	if err := Enhance(context.Background(), s, c, Options{DryRun: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if c.called {
		t.Fatal("dry run called the client")
	}
	p, _ := Payload(testSpec())
	if !strings.Contains(out.String(), p) {
		t.Errorf("dry-run output lacks the payload:\n%s", out.String())
	}
	if !strings.Contains(out.String(), SystemPrompt) || !strings.Contains(out.String(), DefaultModel) {
		t.Errorf("dry-run output lacks the system prompt or model:\n%s", out.String())
	}
	if !reflect.DeepEqual(s, testSpec()) {
		t.Error("dry run changed the spec")
	}
}

func TestEnhanceApplies(t *testing.T) {
	c := &fakeClient{resp: `{"tools":[{"key":"POST /api.php act=addshare","name":"create_share","description":"Create a share.","inputs":{"name":"Share name."}}]}`}
	var out bytes.Buffer
	s := testSpec()
	if err := Enhance(context.Background(), s, c, Options{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if !c.called || c.system != SystemPrompt {
		t.Fatal("client not called with the system prompt")
	}
	p, _ := Payload(testSpec())
	if !strings.Contains(c.prompt, p) {
		t.Error("prompt lacks the payload")
	}
	if s.Tools[1].Name != "create_share" {
		t.Errorf("name = %q", s.Tools[1].Name)
	}
	if !strings.Contains(out.String(), "addshare -> create_share") {
		t.Errorf("summary = %q", out.String())
	}

	c = &fakeClient{err: errors.New("boom")}
	if err := Enhance(context.Background(), testSpec(), c, Options{}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("client error = %v", err)
	}
}

func TestNewAnthropicRequest(t *testing.T) {
	var gotBody map[string]any
	var gotHeader http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		gotBody = nil
		json.Unmarshal(b, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5-5",
			"content":[{"type":"text","text":"{\"tools\":[]}"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	defer srv.Close()
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")

	c := NewAnthropic("test-key", "")
	got, err := c.Complete(context.Background(), "sys", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"tools":[]}` {
		t.Errorf("Complete = %q", got)
	}
	if gotBody["model"] != DefaultModel || gotBody["max_tokens"] != 16000.0 {
		t.Errorf("body = %v", gotBody)
	}
	if gotBody["fallbacks"] != "default" || !strings.Contains(gotHeader.Get("Anthropic-Beta"), "server-side-fallback-2026-07-01") {
		t.Errorf("fallbacks = %v, beta = %q", gotBody["fallbacks"], gotHeader.Get("Anthropic-Beta"))
	}
	if gotHeader.Get("X-Api-Key") != "test-key" {
		t.Errorf("api key header = %q", gotHeader.Get("X-Api-Key"))
	}
	sys, _ := json.Marshal(gotBody["system"])
	msgs, _ := json.Marshal(gotBody["messages"])
	if !strings.Contains(string(sys), `"sys"`) || !strings.Contains(string(msgs), `"hello"`) {
		t.Errorf("system = %s, messages = %s", sys, msgs)
	}

	// A model without server-side fallbacks gets none.
	c = NewAnthropic("test-key", "claude-haiku-4-5")
	if _, err := c.Complete(context.Background(), "sys", "hello"); err != nil {
		t.Fatal(err)
	}
	if _, ok := gotBody["fallbacks"]; ok || gotBody["model"] != "claude-haiku-4-5" {
		t.Errorf("haiku body = %v", gotBody)
	}
}

func TestNewAnthropicRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5-5","content":[],
			"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"no"},"usage":{"input_tokens":1,"output_tokens":0}}`)
	}))
	defer srv.Close()
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	_, err := NewAnthropic("k", "").Complete(context.Background(), "s", "p")
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Errorf("refusal err = %v", err)
	}
}
