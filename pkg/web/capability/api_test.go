package capability

import (
	"net/http"
	"testing"

	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTest() {
	gin.SetMode(gin.TestMode)
	ResetGlobalRegistries()
	ResetRuntimeRegistry()
}

func TestCollectorCollect(t *testing.T) {
	testCases := []struct {
		name           string
		setupRouter    func(engine *gin.Engine) []SyncOption
		expectedSource string
		expectedSvc    string
		verify         func(t *testing.T, req SyncRequest)
	}{
		{
			name: "PrefixAndSource: 带有 source 与 apiPathPrefix 的扫描收集",
			setupRouter: func(engine *gin.Engine) []SyncOption {
				reg := NewRegistry("cmdb", "ssh", "SSH")
				engine.POST("/sftp/delete", reg.Capability("删除文件", "sftp_delete").Handle(func(ctx *gin.Context) {
					ctx.Status(http.StatusNoContent)
				}))
				return []SyncOption{
					WithRouter(engine),
					WithSource("builtin.ssh"),
					WithAPIPathPrefix("/api/plugin-runtime/builtin.ssh"),
				}
			},
			expectedSource: "builtin.ssh",
			expectedSvc:    "cmdb",
			verify: func(t *testing.T, req SyncRequest) {
				require.Len(t, req.APIs, 1)
				assert.Equal(t, "/api/plugin-runtime/builtin.ssh/sftp/delete", req.APIs[0].Path)
				assert.Equal(t, "cmdb:ssh:sftp_delete", req.APIs[0].Code)
			},
		},
		{
			name: "AccessScope: 收集 AccessScope Profile 与模板参数",
			setupRouter: func(engine *gin.Engine) []SyncOption {
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
				return []SyncOption{WithRouter(engine)}
			},
			expectedSvc: "ticket",
			verify: func(t *testing.T, req SyncRequest) {
				require.Len(t, req.APIs, 1)
				assert.Equal(t, pbac.FilterProfile("ticket_history.v1"), req.APIs[0].FilterProfile)

				perm, found := lo.Find(req.Permissions, func(p Permission) bool {
					return p.Code == "ticket:manager:history"
				})
				require.True(t, found)
				require.Len(t, perm.AccessScopePresets, 1)
				assert.Equal(t, "creator", perm.AccessScopePresets[0].Code)
			},
		},
		{
			name: "DefineAndBind: 纯正优雅的 Define + Bind 多 API 聚合模式",
			setupRouter: func(engine *gin.Engine) []SyncOption {
				reg := NewRegistry("iam", "user", "用户中心")
				h1 := func(ctx *gin.Context) { ctx.Status(http.StatusOK) }
				h2 := func(ctx *gin.Context) { ctx.Status(http.StatusOK) }
				h3 := func(ctx *gin.Context) { ctx.Status(http.StatusOK) }

				// 1. 纯粹定义逻辑能力包
				view := reg.Define("查看用户", "view").
					Group("用户中心/用户管理").
					Needs("iam:dept:view")

				// 2. 多个物理 API 干净挂载
				engine.POST("/api/user/list", view.Bind(h1))
				engine.GET("/api/user/detail", view.BindNamed("用户详情", h2))
				engine.GET("/api/user/options", view.BindNamed("用户字典", h3))

				return []SyncOption{WithRouter(engine)}
			},
			expectedSvc: "iam",
			verify: func(t *testing.T, req SyncRequest) {
				// 逻辑能力包只注册了 1 个
				perms := lo.Filter(req.Permissions, func(p Permission, _ int) bool {
					return p.Code == "iam:user:view"
				})
				require.Len(t, perms, 1)
				assert.Equal(t, "查看用户", perms[0].Name)
				assert.Equal(t, "用户中心/用户管理", perms[0].Group)
				assert.Equal(t, []string{"iam:dept:view"}, perms[0].Needs)

				// 物理 API 有 3 个，且完全归属于该 Code
				apis := lo.Filter(req.APIs, func(a ResourceInfo, _ int) bool {
					return a.Code == "iam:user:view"
				})
				require.Len(t, apis, 3)

				apiMap := lo.SliceToMap(apis, func(a ResourceInfo) (string, string) {
					return a.Path, a.Name
				})
				assert.Equal(t, "查看用户", apiMap["/api/user/list"])
				assert.Equal(t, "用户详情", apiMap["/api/user/detail"])
				assert.Equal(t, "用户字典", apiMap["/api/user/options"])
			},
		},
		{
			name: "AttachMultiAPI: 多个物理 API 挂载到同一个权限 Code，主名称不被冲掉",
			setupRouter: func(engine *gin.Engine) []SyncOption {
				reg := NewRegistry("iam", "user", "用户管理")
				h1 := func(ctx *gin.Context) { ctx.Status(http.StatusOK) }
				h2 := func(ctx *gin.Context) { ctx.Status(http.StatusOK) }

				// 主接口声明 "用户列表"
				engine.POST("/api/user/list", reg.Capability("用户列表", "view").Handle(h1))
				// 附属接口复用 view，自命名 "用户详情"
				engine.GET("/api/user/detail", reg.Attach("用户详情", "view").Handle(h2))

				return []SyncOption{WithRouter(engine)}
			},
			expectedSvc: "iam",
			verify: func(t *testing.T, req SyncRequest) {
				// 逻辑权限项只有 1 个，且保持首次声明的主名称
				viewPerms := lo.Filter(req.Permissions, func(p Permission, _ int) bool {
					return p.Code == "iam:user:view"
				})
				require.Len(t, viewPerms, 1)
				assert.Equal(t, "用户列表", viewPerms[0].Name)

				// 物理 API 有 2 个，各自名称独立
				userAPIs := lo.Filter(req.APIs, func(a ResourceInfo, _ int) bool {
					return a.Code == "iam:user:view"
				})
				require.Len(t, userAPIs, 2)

				apiNames := lo.SliceToMap(userAPIs, func(a ResourceInfo) (string, string) {
					return a.Path, a.Name
				})
				assert.Equal(t, "用户列表", apiNames["/api/user/list"])
				assert.Equal(t, "用户详情", apiNames["/api/user/detail"])
			},
		},
		{
			name: "SubModule: 派生独立子模块，动词 view 互不冲突",
			setupRouter: func(engine *gin.Engine) []SyncOption {
				baseReg := NewRegistry("task", "codebook", "脚本引擎")
				versionReg := baseReg.Sub("version", "版本管理") // 自动拼接为 "脚本引擎/版本管理"
				projectReg := baseReg.Sub("project", "脚本引擎/项目管理")

				h1 := func(ctx *gin.Context) { ctx.Status(http.StatusOK) }
				h2 := func(ctx *gin.Context) { ctx.Status(http.StatusOK) }

				engine.POST("/api/version/list", versionReg.Capability("版本列表", "view").Handle(h1))
				engine.POST("/api/project/list", projectReg.Capability("项目列表", "view").Handle(h2))

				return []SyncOption{WithRouter(engine)}
			},
			expectedSvc: "task",
			verify: func(t *testing.T, req SyncRequest) {
				codes := lo.Map(req.Permissions, func(p Permission, _ int) string { return p.Code })
				assert.Contains(t, codes, "task:version:view")
				assert.Contains(t, codes, "task:project:view")

				versionPerm, _ := lo.Find(req.Permissions, func(p Permission) bool { return p.Code == "task:version:view" })
				assert.Equal(t, "版本列表", versionPerm.Name)
				assert.Equal(t, "脚本引擎/版本管理", versionPerm.Group)

				projectPerm, _ := lo.Find(req.Permissions, func(p Permission) bool { return p.Code == "task:project:view" })
				assert.Equal(t, "项目列表", projectPerm.Name)
				assert.Equal(t, "脚本引擎/项目管理", projectPerm.Group)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setupTest()
			engine := gin.New()
			options := tc.setupRouter(engine)

			req := NewCollector().Collect(options...)

			if tc.expectedSource != "" {
				assert.Equal(t, tc.expectedSource, req.Source)
			}
			if tc.expectedSvc != "" {
				assert.Equal(t, tc.expectedSvc, req.Service)
			}

			tc.verify(t, req)
		})
	}
}

func TestDuplicateCapabilityDefense(t *testing.T) {
	testCases := []struct {
		name         string
		operations   func(reg IRegistry)
		expectedCode string
		expectedName string
	}{
		{
			name: "手误多次调用 Capability 时，保留首次声明的权限名称",
			operations: func(reg IRegistry) {
				reg.Capability("模型主列表", "view")
				reg.Capability("模型辅助列表", "view")
			},
			expectedCode: "cmdb:model:view",
			expectedName: "模型主列表",
		},
		{
			name: "首次声明无分组，后声明携带分组时自动增量补充",
			operations: func(reg IRegistry) {
				reg.Capability("资产列表", "view")
				reg.Capability("资产辅助", "view").Group("资产管理")
			},
			expectedCode: "cmdb:model:view",
			expectedName: "资产列表",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setupTest()
			reg := NewRegistry("cmdb", "model", "")
			tc.operations(reg)

			p, ok := reg.GetPermission(tc.expectedCode)
			require.True(t, ok)
			assert.Equal(t, tc.expectedName, p.Name)
		})
	}
}

func TestSyncRequestOwnerKey(t *testing.T) {
	testCases := []struct {
		name     string
		req      SyncRequest
		expected string
	}{
		{
			name:     "无 source 时直接返回 service",
			req:      SyncRequest{Service: "cmdb"},
			expected: "cmdb",
		},
		{
			name:     "有 source 时返回 service@source",
			req:      SyncRequest{Service: "cmdb", Source: "builtin.ssh"},
			expected: "cmdb@builtin.ssh",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.req.OwnerKey())
		})
	}
}
