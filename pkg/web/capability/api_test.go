package capability

import (
	"net/http"
	"testing"

	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/gin-gonic/gin"
)

func TestCollectorCollectWithSourceAndAPIPathPrefix(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	reg := NewRegistry("cmdb", "ssh", "SSH")
	engine.POST("/sftp/delete", reg.Capability("删除文件", "sftp_delete").Handle(func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	}))

	collector := NewCollector()
	req := collector.Collect(
		WithRouter(engine),
		WithSource("builtin.ssh"),
		WithAPIPathPrefix("/api/plugin-runtime/builtin.ssh"),
	)

	if req.Source != "builtin.ssh" {
		t.Fatalf("expected source builtin.ssh, got %s", req.Source)
	}
	if req.Service != "cmdb" {
		t.Fatalf("expected service cmdb, got %s", req.Service)
	}
	if len(req.APIs) != 1 {
		t.Fatalf("expected 1 api, got %d", len(req.APIs))
	}
	if req.APIs[0].Path != "/api/plugin-runtime/builtin.ssh/sftp/delete" {
		t.Fatalf("unexpected api path: %s", req.APIs[0].Path)
	}
}

func TestCollectorCollectsAccessScopeProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	registry := NewRegistry("ticket", "manager", "工单管理")
	preset := pbac.AccessScopePreset{
		Code: "creator", Name: "仅本人创建",
		Expression: &pbac.AccessScope{Predicate: &pbac.Predicate{
			Key: "ticket:create_by", Operator: pbac.StringEquals,
			Values: []pbac.Operand{pbac.Ref(pbac.PrincipalUsername)},
		}},
	}
	engine.POST("/history", registry.Capability("历史工单", "history").
		AccessScope(pbac.FilterProfile("ticket_history.v1"), preset).
		Handle(func(ctx *gin.Context) {
			ctx.Status(http.StatusNoContent)
		}))

	req := NewCollector().Collect(WithRouter(engine))
	if len(req.APIs) != 1 {
		t.Fatalf("expected 1 API, got %d", len(req.APIs))
	}
	if req.APIs[0].FilterProfile != "ticket_history.v1" {
		t.Fatalf("unexpected filter profile: %q", req.APIs[0].FilterProfile)
	}
	var permission Permission
	for _, candidate := range req.Permissions {
		if candidate.Code == "ticket:manager:history" {
			permission = candidate
			break
		}
	}
	if len(permission.AccessScopePresets) != 1 || permission.AccessScopePresets[0].Code != "creator" {
		t.Fatalf("unexpected AccessScope presets: %#v", req.Permissions)
	}
}

func TestSyncRequestOwnerKey(t *testing.T) {
	if got := (SyncRequest{Service: "cmdb"}).OwnerKey(); got != "cmdb" {
		t.Fatalf("unexpected owner key without source: %s", got)
	}
	if got := (SyncRequest{Service: "cmdb", Source: "builtin.ssh"}).OwnerKey(); got != "cmdb@builtin.ssh" {
		t.Fatalf("unexpected owner key with source: %s", got)
	}
}
