package spec

import (
	"path/filepath"
	"reflect"
	"testing"
)

func toolByKey(s *Spec, key string) *Tool {
	for i := range s.Tools {
		if s.Tools[i].Source.Key == key {
			return &s.Tools[i]
		}
	}
	return nil
}

const disksKey = "POST /api.php act=getdisklist"

func TestMergeKeepsHandEdits(t *testing.T) {
	existing := sampleSpec()
	existing.Tools[0].Name = "get_disks" // Generated["name"] still holds FieldHash("list_disks")
	existing.Tools[0].Enabled = false
	existing.Tools[1].Inputs[0].Description = "Name of the new share"

	fresh := sampleSpec()
	fresh.Tools[0].Source.Samples = 7
	fresh.Tools[0].Response.Schema = map[string]any{"type": "object", "properties": map[string]any{"fresh": map[string]any{"type": "string"}}}
	fresh.Tools[0].Request.Body = map[string]any{"act": "getdisklist", "v": 2}
	fresh.Tools[1].Inputs[0].Example = "backups"
	stampGenerated(fresh)

	merged := Merge(existing, fresh)
	got := toolByKey(merged, disksKey)
	if got == nil {
		t.Fatal("tool lost")
	}
	if got.Name != "get_disks" {
		t.Errorf("hand-edited name = %q, want get_disks", got.Name)
	}
	if got.Enabled {
		t.Error("hand-edited enabled: false was overwritten")
	}
	if got.Source.Samples != 7 {
		t.Errorf("samples = %d, want the fresh 7", got.Source.Samples)
	}
	if !reflect.DeepEqual(got.Response.Schema, fresh.Tools[0].Response.Schema) {
		t.Errorf("schema not refreshed: %v", got.Response.Schema)
	}
	if got.Request.Body["v"] != 2 {
		t.Errorf("request not refreshed: %v", got.Request.Body)
	}
	if got.Generated["name"] != FieldHash("list_disks") || got.Generated["enabled"] != FieldHash(true) {
		t.Errorf("Generated not refreshed from fresh values: %v", got.Generated)
	}
	share := toolByKey(merged, "POST /api.php act=addshare")
	if share.Inputs[0].Description != "Name of the new share" {
		t.Errorf("hand-edited inputs overwritten: %+v", share.Inputs)
	}
	if err := merged.Validate(); err != nil {
		t.Errorf("merged spec invalid: %v", err)
	}

	// The edit survives another analyze run.
	again := Merge(merged, fresh)
	if toolByKey(again, disksKey).Name != "get_disks" || toolByKey(again, disksKey).Enabled {
		t.Error("hand edits lost on the second merge")
	}
}

func TestMergeTakesUnEditedFields(t *testing.T) {
	existing := sampleSpec()
	fresh := sampleSpec()
	fresh.Tools[0].Description = "Fresh description."
	fresh.Tools[0].Kind = "change"
	fresh.Tools[1].Inputs = append(fresh.Tools[1].Inputs, Input{Name: "comment", Type: "string", In: "body", Field: "comment"})
	stampGenerated(fresh)

	merged := Merge(existing, fresh)
	got := toolByKey(merged, disksKey)
	if got.Description != "Fresh description." {
		t.Errorf("unedited description = %q, want the fresh one", got.Description)
	}
	if got.Kind != "change" {
		t.Errorf("unedited kind = %q, want the fresh one", got.Kind)
	}
	if n := len(toolByKey(merged, "POST /api.php act=addshare").Inputs); n != 2 {
		t.Errorf("unedited inputs not refreshed: %d inputs", n)
	}
	if got.Name != "list_disks" {
		t.Errorf("name = %q", got.Name)
	}
}

func TestMergeAddsNewKeepsMissing(t *testing.T) {
	existing := sampleSpec()
	existing.Tools = append(existing.Tools, Tool{
		Name: "old_only", Kind: "read", Enabled: true,
		Request: Request{Method: "GET", Path: "/old"},
		Source:  Source{Key: "GET /old", Samples: 1},
	})
	stampGenerated(existing)

	fresh := sampleSpec()
	fresh.Tools = append(fresh.Tools, Tool{
		Name: "new_only", Kind: "read", Enabled: true,
		Request: Request{Method: "GET", Path: "/new"},
		Source:  Source{Key: "GET /new", Samples: 1},
	})
	stampGenerated(fresh)

	merged := Merge(existing, fresh)
	if toolByKey(merged, "GET /old") == nil {
		t.Error("a tool missing from the new recording was deleted")
	}
	if toolByKey(merged, "GET /new") == nil {
		t.Error("a new tool was not added")
	}
	if len(merged.Tools) != len(sampleSpec().Tools)+2 {
		t.Errorf("tools = %d", len(merged.Tools))
	}
	// Existing order first, new tools appended.
	if merged.Tools[0].Source.Key != disksKey || merged.Tools[len(merged.Tools)-1].Source.Key != "GET /new" {
		t.Errorf("order = %s ... %s", merged.Tools[0].Source.Key, merged.Tools[len(merged.Tools)-1].Source.Key)
	}
	if err := merged.Validate(); err != nil {
		t.Errorf("merged spec invalid: %v", err)
	}
}

func TestMergeAuthPrefersFreshUnlessEdited(t *testing.T) {
	// Unedited: the fresh auth block wins.
	existing := sampleSpec()
	fresh := sampleSpec()
	fresh.Auth.ReloginBodyContains = "session expired"
	stampGenerated(fresh)
	merged := Merge(existing, fresh)
	if merged.Auth.ReloginBodyContains != "session expired" {
		t.Errorf("unedited auth not refreshed: %q", merged.Auth.ReloginBodyContains)
	}
	if merged.AuthGenerated != FieldHash(fresh.Auth) {
		t.Errorf("AuthGenerated = %q, want the fresh hash", merged.AuthGenerated)
	}

	// Edited: the existing auth block is kept as a unit.
	existing = sampleSpec()
	existing.Auth.ReloginOn = []int{401, 403, 419}
	merged = Merge(existing, fresh)
	if !reflect.DeepEqual(merged.Auth.ReloginOn, []int{401, 403, 419}) || merged.Auth.ReloginBodyContains != "not logged in" {
		t.Errorf("hand-edited auth overwritten: %+v", merged.Auth)
	}
	again := Merge(merged, fresh)
	if !reflect.DeepEqual(again.Auth.ReloginOn, []int{401, 403, 419}) {
		t.Error("auth edit lost on the second merge")
	}
}

func TestMergeWithoutGeneratedKeepsExisting(t *testing.T) {
	// A hand-written spec has no hashes: treat everything as edited.
	existing := sampleSpec()
	existing.AuthGenerated = ""
	existing.Tools[0].Generated = nil
	existing.Tools[0].Description = "Mine."
	fresh := sampleSpec()
	fresh.Tools[0].Description = "Fresh."
	fresh.Auth.ReloginOn = []int{401}
	stampGenerated(fresh)
	merged := Merge(existing, fresh)
	if toolByKey(merged, disksKey).Description != "Mine." {
		t.Error("description without a hash was overwritten")
	}
	if !reflect.DeepEqual(merged.Auth.ReloginOn, []int{401, 403}) {
		t.Error("auth without a hash was overwritten")
	}
}

func TestMergeNameCollisions(t *testing.T) {
	// The user renamed add_share to "reboot_now"; a new operation is also
	// named reboot_now by analysis. The user's name wins.
	existing := sampleSpec()
	existing.Tools[1].Name = "reboot_now"
	fresh := sampleSpec()
	fresh.Tools = append(fresh.Tools, Tool{
		Name: "reboot_now", Kind: "destructive", Enabled: true,
		Request: Request{Method: "POST", Path: "/reboot"},
		Source:  Source{Key: "POST /reboot", Samples: 1},
	})
	stampGenerated(fresh)
	merged := Merge(existing, fresh)
	if toolByKey(merged, "POST /api.php act=addshare").Name != "reboot_now" {
		t.Error("hand-edited name lost to a collision")
	}
	if got := toolByKey(merged, "POST /reboot").Name; got != "reboot_now_2" {
		t.Errorf("new colliding tool = %q, want reboot_now_2", got)
	}
	if err := merged.Validate(); err != nil {
		t.Errorf("merged spec invalid: %v", err)
	}
}

func TestMergeKeepsServiceAndSurvivesSaveLoad(t *testing.T) {
	dir := t.TempDir()
	existing := sampleSpec()
	existing.Service.Name = "tos"
	existing.Tools[0].Name = "get_disks"
	path := filepath.Join(dir, "tos.spec.yaml")
	if err := Save(path, existing); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	fresh := sampleSpec()
	fresh.Service.Hosts = []string{"192.168.1.10:8181", "nas.local"}
	fresh.Tools[1].Description = "Fresh share text."
	stampGenerated(fresh)
	merged := Merge(loaded, fresh)
	if merged.Service.Name != "tos" {
		t.Errorf("service name = %q, want the existing tos", merged.Service.Name)
	}
	if !reflect.DeepEqual(merged.Service.Hosts, []string{"192.168.1.10:8181", "nas.local"}) {
		t.Errorf("hosts = %v", merged.Service.Hosts)
	}
	if toolByKey(merged, disksKey).Name != "get_disks" {
		t.Error("rename lost after save and load")
	}
	if toolByKey(merged, "POST /api.php act=addshare").Description != "Fresh share text." {
		t.Error("an unedited field was treated as edited after save and load")
	}
	if merged.Auth.Login == nil || merged.AuthGenerated != FieldHash(fresh.Auth) {
		t.Error("unedited auth was treated as edited after save and load")
	}
}

func TestMergeNil(t *testing.T) {
	s := sampleSpec()
	if got := Merge(nil, s); got == nil || len(got.Tools) != len(s.Tools) {
		t.Fatal("Merge(nil, fresh) should return fresh")
	}
	if got := Merge(s, nil); got == nil || len(got.Tools) != len(s.Tools) {
		t.Fatal("Merge(existing, nil) should return existing")
	}
}
