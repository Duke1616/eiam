package ingestion

import (
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/Duke1616/eiam/pkg/web/capability"
)

func TestFromSyncRequestPreservesSource(t *testing.T) {
	snap := FromSyncRequest(capability.SyncRequest{
		Service: "cmdb",
		Source:  "builtin.ssh",
		Permissions: []capability.Permission{
			{
				Code: "cmdb:ssh:sftp_delete", Name: "删除文件",
				AccessScopePresets: []pbac.AccessScopePreset{{
					Code: "owner", Name: "仅本人",
					Expression: &pbac.AccessScope{Predicate: &pbac.Predicate{
						Key: "file:owner", Operator: pbac.StringEquals,
						Values: []pbac.Operand{pbac.Ref(pbac.PrincipalUsername)},
					}},
				}},
			},
		},
		APIs: []capability.ResourceInfo{
			{
				Name:          "删除文件",
				Method:        "POST",
				Path:          "/api/plugin-runtime/builtin.ssh/sftp/delete",
				Code:          "cmdb:ssh:sftp_delete",
				FilterProfile: pbac.FilterProfile("cmdb_file_visibility"),
			},
		},
	})

	if snap.Source != "builtin.ssh" {
		t.Fatalf("expected source builtin.ssh, got %s", snap.Source)
	}
	if len(snap.Permissions) != 1 || snap.Permissions[0].Source != "builtin.ssh" {
		t.Fatalf("unexpected permissions snapshot: %#v", snap.Permissions)
	}
	if len(snap.Permissions[0].AccessScopePresets) != 1 || snap.Permissions[0].AccessScopePresets[0].Code != "owner" {
		t.Fatalf("unexpected AccessScope presets: %#v", snap.Permissions[0].AccessScopePresets)
	}
	if len(snap.APIs) != 1 || snap.APIs[0].Source != "builtin.ssh" {
		t.Fatalf("unexpected api snapshot: %#v", snap.APIs)
	}
	if snap.APIs[0].FilterProfile != "cmdb_file_visibility" {
		t.Fatalf("unexpected API filter profile: %q", snap.APIs[0].FilterProfile)
	}
	if len(snap.Bindings["cmdb:ssh:sftp_delete"]) != 1 {
		t.Fatalf("unexpected bindings: %#v", snap.Bindings)
	}
}

func TestSnapshotRejectsInvalidAccessScopePreset(t *testing.T) {
	snapshot := Snapshot{Permissions: []domain.Permission{{
		Code:               "ticket:history",
		AccessScopePresets: []pbac.AccessScopePreset{{Code: "owner", Name: "仅本人"}},
	}}}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("expected incomplete AccessScope preset to be rejected")
	}
}

func TestFromSyncRequestDeduplicatesBindings(t *testing.T) {
	snap := FromSyncRequest(capability.SyncRequest{
		Service: "test-service",
		Source:  "test-source",
		Permissions: []capability.Permission{
			{Code: "test:view", Name: "查看"},
		},
		APIs: []capability.ResourceInfo{
			{Code: "test:view", Method: "GET", Path: "/test/items"},
			{Code: "test:view", Method: "GET", Path: "/test/items"}, // 重复注册同一路由端点
		},
	})

	if len(snap.Bindings["test:view"]) != 1 {
		t.Fatalf("expected duplicate URNs to be deduplicated, got: %#v", snap.Bindings["test:view"])
	}
}
