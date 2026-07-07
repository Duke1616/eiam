package ingestion

import (
	"testing"

	"github.com/Duke1616/eiam/pkg/web/capability"
)

func TestFromSyncRequestPreservesSource(t *testing.T) {
	snap := FromSyncRequest(capability.SyncRequest{
		Service: "cmdb",
		Source:  "builtin.ssh",
		Permissions: []capability.Permission{
			{Code: "cmdb:ssh:sftp_delete", Name: "删除文件"},
		},
		APIs: []capability.ResourceInfo{
			{
				Name:   "删除文件",
				Method: "POST",
				Path:   "/api/plugin-runtime/builtin.ssh/sftp/delete",
				Code:   "cmdb:ssh:sftp_delete",
			},
		},
	})

	if snap.Source != "builtin.ssh" {
		t.Fatalf("expected source builtin.ssh, got %s", snap.Source)
	}
	if len(snap.Permissions) != 1 || snap.Permissions[0].Source != "builtin.ssh" {
		t.Fatalf("unexpected permissions snapshot: %#v", snap.Permissions)
	}
	if len(snap.APIs) != 1 || snap.APIs[0].Source != "builtin.ssh" {
		t.Fatalf("unexpected api snapshot: %#v", snap.APIs)
	}
	if len(snap.Bindings["cmdb:ssh:sftp_delete"]) != 1 {
		t.Fatalf("unexpected bindings: %#v", snap.Bindings)
	}
}
