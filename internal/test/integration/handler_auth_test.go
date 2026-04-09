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

	testTid int64
	testUid int64
}

func (s *HandlerAuthTestSuite) SetupSuite() {
	dir, _ := os.Getwd()
	viper.SetConfigFile(filepath.Join(dir, "../config/config.yaml"))
	err := viper.ReadInConfig()
	s.Require().NoError(err)

	deps, err := testioc.InitPermissionSuiteDeps()
	s.Require().NoError(err)

	s.db = deps.DB
	s.enforcer = deps.Enforcer
	s.permSvc = deps.PermSvc
	s.tenantSvc = deps.TenantSvc
	s.resourceSvc = deps.ResourceSvc
	s.roleSvc = deps.RoleSvc
	s.ctrl = gomock.NewController(s.T())

	sp := testmocks.NewMockProvider(s.ctrl)
	sp.EXPECT().Get(gomock.Any()).AnyTimes().DoAndReturn(func(ctx *gctx.Context) (session.Session, error) {
		if sess, ok := ctx.Get("_session"); ok {
			return sess.(session.Session), nil
		}
		return nil, nil
	})
	session.SetDefaultProvider(sp)

	gin.SetMode(gin.TestMode)
	server := gin.New()
	server.Use(func(ctx *gin.Context) {
		newCtx := ctxutil.WithTenantID(ctx.Request.Context(), s.testTid)
		newCtx = ctxutil.WithUserID(newCtx, s.testUid)
		ctx.Request = ctx.Request.WithContext(newCtx)
		ctx.Set("_session", session.NewMemorySession(session.Claims{Uid: s.testUid}))
	})
	server.Use(middleware.CheckPermission(s.permSvc))

	registry := capability.NewRegistry("iam", "user", "用户管理")
	server.POST("/api/user/add", registry.Capability("新增用户", "add").
		Handle(ginx.W(func(ctx *ginx.Context) (ginx.Result, error) {
			return ginx.Result{Data: "OK"}, nil
		})),
	)
	s.server = server
}

func (s *HandlerAuthTestSuite) TearDownSubTest() {
	s.clearAll()
}

func (s *HandlerAuthTestSuite) clearAll() {
	s.db.Exec("DROP TABLE IF EXISTS goose_db_version")
	s.db.Exec("DELETE FROM casbin_rule")
	s.db.Exec("DELETE FROM permission")
	s.db.Exec("DELETE FROM permission_binding")
	s.db.Exec("DELETE FROM role")
	s.db.Exec("DELETE FROM tenant")
	s.db.Exec("DELETE FROM membership")
	s.db.Exec("DELETE FROM api")
	_ = s.enforcer.LoadPolicy()
}

func (s *HandlerAuthTestSuite) TestAPIAuthorization() {

	testcases := []struct {
		name     string
		before   func(ctx context.Context, tid int64)
		wantCode int
	}{
		{
			name: "场景1：用户未注册任何角色和 API -> 预期 403",
			before: func(ctx context.Context, tid int64) {
				// 核心修复：切换到非 Owner 的普通用户，防止被 ADMIN 角色放行
				s.testUid = 1001
				// 这里注册 API 实体，但不要给用户任何授权
				api := domain.API{Service: "iam", Method: "POST", Path: "/api/user/add"}
				_, err := s.resourceSvc.CreateAPI(ctx, api)
				s.Require().NoError(err)

				// 即使建立了能力项，不绑定用户也应阻断
				pid, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "iam:user:add"})
				_ = s.permSvc.BindResourcesToPermission(ctx, pid, "iam:user:add", []string{api.URN()})
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "场景2：用户拥有其他权限但没有当前接口权限 -> 预期 403",
			before: func(ctx context.Context, tid int64) {
				s.testUid = 1002
				// 1. 注册 API 并关联其真正的权限码 iam:user:add
				api := domain.API{Service: "iam", Method: "POST", Path: "/api/user/add"}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)
				pid, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "iam:user:add"})
				_ = s.permSvc.BindResourcesToPermission(ctx, pid, "iam:user:add", []string{api.URN()})

				// 2. 赋予用户一个完全不相关的权限 (如 iam:user:view)
				_, _ = s.roleSvc.Create(ctx, domain.Role{Code: "OPERATOR", TenantID: tid})
				_ = s.roleSvc.UpdatePolicies(ctx, "OPERATOR", []domain.Policy{{
					Type: domain.CustomPolicy,
					Statement: []domain.Statement{{Effect: domain.Allow, Action: []string{"iam:user:view"}, Resource: []string{"*"}}},
				}})
				_, _ = s.permSvc.AssignRoleToUser(ctx, s.testUid, "OPERATOR")
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "场景3：用户拥有精准匹配的角色权限 -> 预期 200",
			before: func(ctx context.Context, tid int64) {
				s.testUid = 1003
				api := domain.API{Service: "iam", Method: "POST", Path: "/api/user/add"}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)

				pid, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "iam:user:add"})
				_ = s.permSvc.BindResourcesToPermission(ctx, pid, "iam:user:add", []string{api.URN()})

				_, _ = s.roleSvc.Create(ctx, domain.Role{Code: "ADMIN_ROLE", TenantID: tid})
				_ = s.roleSvc.UpdatePolicies(ctx, "ADMIN_ROLE", []domain.Policy{{
					Type:      domain.CustomPolicy,
					Statement: []domain.Statement{{Effect: domain.Allow, Action: []string{"iam:user:add"}, Resource: []string{"*"}}},
				}})
				_, _ = s.permSvc.AssignRoleToUser(ctx, s.testUid, "ADMIN_ROLE")
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			// 初始化干净的租户环境
			tid, err := s.tenantSvc.CreateTenant(context.Background(), "单元", "unit", 9999)
			s.Require().NoError(err)
			s.testTid = tid
			ctx := ctxutil.WithTenantID(context.Background(), tid)

			tc.before(ctx, tid)

			req, _ := http.NewRequest(http.MethodPost, "/api/user/add", nil)
			recorder := httptest.NewRecorder()
			s.server.ServeHTTP(recorder, req)

			s.Assert().Equal(tc.wantCode, recorder.Code)
		})
	}
}

func TestHandlerAuth(t *testing.T) {
	suite.Run(t, new(HandlerAuthTestSuite))
}
