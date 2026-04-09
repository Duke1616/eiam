package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/pkg/middleware"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/internal/service/tenant"
	testioc "github.com/Duke1616/eiam/internal/test/ioc"
	testmocks "github.com/Duke1616/eiam/internal/test/mocks"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/casbin/casbin/v2"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"
)

type HandlerAuthTestSuite struct {
	suite.Suite

	db       *gorm.DB
	enforcer *casbin.SyncedEnforcer
	server   *gin.Engine
	ctrl     *gomock.Controller

	permSvc     permission.IPermissionService
	tenantSvc   tenant.ITenantService
	resourceSvc resource.IResourceService
	roleSvc     role.IRoleService

	// 测试元数据
	testUid  int64
	testTid  int64
	testCode string
}

func (s *HandlerAuthTestSuite) SetupSuite() {
	// 1. 初始化运行配置项
	dir, err := os.Getwd()
	require.NoError(s.T(), err)
	viper.SetConfigFile(filepath.Join(dir, "../config/config.yaml"))
	err = viper.ReadInConfig()
	require.NoError(s.T(), err, "请确保能在当前目录的上两级找到 config/config.yaml")

	// 2. 初始化集成测试依赖 (数据库、Casbin、Service)
	deps, err := testioc.InitPermissionSuiteDeps()
	require.NoError(s.T(), err)

	s.db = deps.DB
	s.enforcer = deps.Enforcer

	s.permSvc = deps.PermSvc
	s.tenantSvc = deps.TenantSvc
	s.resourceSvc = deps.ResourceSvc
	s.roleSvc = deps.RoleSvc
	s.testUid = 9527
	s.testCode = "iam:user:add"
	s.ctrl = gomock.NewController(s.T())

	// 使用 MockGen 生成的 Provider
	sp := testmocks.NewMockProvider(s.ctrl)
	sp.EXPECT().Get(gomock.Any()).AnyTimes().DoAndReturn(func(ctx *gctx.Context) (session.Session, error) {
		if sess, ok := ctx.Get("_session"); ok {
			return sess.(session.Session), nil
		}
		return nil, nil
	})
	session.SetDefaultProvider(sp)

	// 2. 初始化测试租户
	tid, err := s.tenantSvc.CreateTenant(context.Background(), "核心业务部", "core-biz", s.testUid)
	require.NoError(s.T(), err)
	s.testTid = tid

	// 3. 构造 Web 服务器并挂载中间件
	gin.SetMode(gin.TestMode)
	server := gin.New()

	// 注入模拟 Session 及 租户上下文
	server.Use(func(ctx *gin.Context) {
		newCtx := ctxutil.WithTenantID(ctx.Request.Context(), s.testTid)
		newCtx = ctxutil.WithUserID(newCtx, s.testUid)
		ctx.Request = ctx.Request.WithContext(newCtx)
		ctx.Set("_session", session.NewMemorySession(session.Claims{
			Uid: s.testUid,
		}))
	})

	// 挂载鉴权中间件
	server.Use(middleware.CheckPermission(s.permSvc))

	// 注册带装饰器的测试接口
	registry := capability.NewRegistry("iam", "user", "用户管理")
	server.POST("/api/user/add", registry.Capability("新增用户", "add").
		Handle(ginx.W(func(ctx *ginx.Context) (ginx.Result, error) {
			return ginx.Result{Data: "OK"}, nil
		})),
	)

	s.server = server
}

func (s *HandlerAuthTestSuite) TearDownTest() {
}

func (s *HandlerAuthTestSuite) TearDownSubTest() {
	s.clearAll()
}

func (s *HandlerAuthTestSuite) TearDownSuite() {
}

func (s *HandlerAuthTestSuite) TestAPIAuthorization() {

	testCases := []struct {
		name     string
		before   func(t *testing.T)
		wantCode int
	}{
		{
			name: "场景1：用户未获得授权 -> 预期 403",
			before: func(t *testing.T) {
				// 确保环境中没有相关策略
				s.db.Exec("DELETE FROM casbin_rule")
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "场景2：用户获得授权 -> 预期 403 (权限不匹配)",
			before: func(t *testing.T) {
				ctx := ctxutil.WithTenantID(context.Background(), s.testTid)

				// 切换为一个全新的用户，避开租户所有者的 ADMIN 角色
				s.testUid = 9999

				// 1. 创建并注册 API (这一步对 CheckAPI 很关键)
				api := domain.API{
					Service: "iam",
					Method:  "POST",
					Path:    "/api/user/add",
					Name:    "新增用户",
				}
				_, err := s.resourceSvc.CreateAPI(ctx, api)
				require.NoError(t, err)

				// 2. 创建权限点并绑定到 API URN
				permId, err := s.permSvc.CreatePermission(ctx, domain.Permission{
					Code: s.testCode,
					Name: "用户创建权",
				})
				require.NoError(t, err)
				err = s.permSvc.BindResourcesToPermission(ctx, permId, s.testCode, []string{api.URN()})
				require.NoError(t, err)

				// 3. 创建并配置角色（仅给予删除权限）
				_, err = s.roleSvc.Create(ctx, domain.Role{
					Code: "OPERATOR",
					Name: "普通操作员",
					Policies: []domain.Policy{
						{
							Type: domain.SystemPolicy,
							Statement: []domain.Statement{
								{
									Effect:   domain.Allow,
									Action:   []string{"iam:user:delete"},
									Resource: []string{"*"},
								},
							},
						},
					},
				})
				require.NoError(t, err)

				// 4. 将新用户加入该角色
				_, err = s.permSvc.AssignRoleToUser(ctx, s.testUid, "OPERATOR")
				require.NoError(t, err)
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "场景3：用户获得授权 -> 预期 200 (权限精准匹配)",
			before: func(t *testing.T) {
				ctx := ctxutil.WithTenantID(context.Background(), s.testTid)

				// 使用普通业务用户
				s.testUid = 7777

				// 1. 创建并注册 API
				api := domain.API{
					Service: "iam",
					Method:  "POST",
					Path:    "/api/user/add",
					Name:    "新增用户",
				}
				_, err := s.resourceSvc.CreateAPI(ctx, api)
				require.NoError(t, err)

				// 2. 创建权限点并绑定到 API URN
				permId, err := s.permSvc.CreatePermission(ctx, domain.Permission{
					Code: s.testCode,
					Name: "用户创建权",
				})
				require.NoError(t, err)
				err = s.permSvc.BindResourcesToPermission(ctx, permId, s.testCode, []string{api.URN()})
				require.NoError(t, err)

				// 3. 创建并配置角色（给予正确的 Add 权限）
				_, err = s.roleSvc.Create(ctx, domain.Role{
					Code: "MANAGER",
					Name: "管理员",
					Policies: []domain.Policy{
						{
							Type: domain.SystemPolicy,
							Statement: []domain.Statement{
								{
									Effect:   domain.Allow,
									Action:   []string{s.testCode},
									Resource: []string{"*"},
								},
							},
						},
					},
				})
				require.NoError(t, err)

				// 4. 将用户加入该角色
				_, err = s.permSvc.AssignRoleToUser(ctx, s.testUid, "MANAGER")
				require.NoError(t, err)
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			tc.before(s.T())

			req, err := http.NewRequest(http.MethodPost, "/api/user/add", nil)
			require.NoError(s.T(), err)
			recorder := httptest.NewRecorder()
			s.server.ServeHTTP(recorder, req)

			assert.Equal(s.T(), tc.wantCode, recorder.Code)
		})
	}
}

func (s *HandlerAuthTestSuite) clearAll() {
	// 清理测试环境遗留数据，确保隔离
	t := s.T()
	t.Helper()

	// 仅清理非系统级别的租户数据，保留 Goose 注入的 0 号租户种子角色
	s.db.Exec("DELETE FROM casbin_rule")
	s.db.Exec("DELETE FROM permission")
	s.db.Exec("DELETE FROM permission_binding")
	s.db.Exec("DELETE FROM role")
	s.db.Exec("DELETE FROM tenant")
	s.db.Exec("DELETE FROM membership")
	s.db.Exec("DELETE FROM api")
}

func TestHandlerAuth(t *testing.T) {
	suite.Run(t, new(HandlerAuthTestSuite))
}
