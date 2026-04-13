package integration

import (
	"context"
	"fmt"
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
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"
)

type HandlerAuthTestSuite struct {
	suite.Suite

	db       *gorm.DB
	enforcer *casbin.SyncedEnforcer
	ctrl     *gomock.Controller

	permSvc     permission.IPermissionService
	tenantSvc   tenant.ITenantService
	roleSvc     role.IRoleService
	resourceSvc resource.IResourceService

	server  *gin.Engine
	testUid int64
	testTid int64
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

	// 还原 Session Mock 逻辑
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

	// 注册测试接口
	registry := capability.NewRegistry("iam", "user", "用户管理")
	server.POST("/api/user/add", registry.Capability("新增用户", "add").
		Handle(ginx.W(func(ctx *ginx.Context) (ginx.Result, error) {
			return ginx.Result{Data: "OK"}, nil
		})),
	)
	s.server = server
}

func (s *HandlerAuthTestSuite) TearDownTest() {
	s.clearAll()
}

func (s *HandlerAuthTestSuite) ensureAdminRole(ctx context.Context) {
	_, _ = s.roleSvc.Create(ctx, domain.Role{Code: "admin", Name: "租户管理员"})
	_, _ = s.roleSvc.Create(ctx, domain.Role{
		Code: "super_admin",
		Name: "全局管理员",
		InlinePolicies: []domain.Policy{
			{
				Code:      "root_allow_all",
				Statement: []domain.Statement{{Effect: domain.Allow, Action: []string{"*"}, Resource: []string{"*"}}},
			},
		},
	})
	_, _ = s.permSvc.AssignRoleInheritance(ctx, "admin", "super_admin")
}

func (s *HandlerAuthTestSuite) clearAll() {
	s.db.Exec("DELETE FROM `tenant`")
	s.db.Exec("DELETE FROM `membership`")
	s.db.Exec("DELETE FROM `role`")
	s.db.Exec("DELETE FROM `policy`")
	s.db.Exec("DELETE FROM `role_policy_attachment`")
	s.db.Exec("DELETE FROM `api`")
	s.db.Exec("DELETE FROM `permission`")
	s.db.Exec("DELETE FROM `permission_binding`")
	s.db.Exec("DELETE FROM `casbin_rule`")
}

func (s *HandlerAuthTestSuite) TestAPIAuthorization() {
	testcases := []struct {
		name     string
		before   func(ctx context.Context, tid int64)
		wantCode int
	}{
		{
			name: "场景1: 用户未注册任何角色和 API -> 预期 403",
			before: func(ctx context.Context, tid int64) {
				s.testUid = 1001
				api := domain.API{Service: "iam", Method: "POST", Path: "/api/user/add"}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)
				pid, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "iam:user:add"})
				_ = s.permSvc.BindResourcesToPermission(ctx, pid, "iam:user:add", []string{api.URN()})
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "场景2: 用户拥有其他权限但没有当前接口权限 -> 预期 403",
			before: func(ctx context.Context, tid int64) {
				s.testUid = 1002
				api := domain.API{Service: "iam", Method: "POST", Path: "/api/user/add"}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)
				pid, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "iam:user:add"})
				_ = s.permSvc.BindResourcesToPermission(ctx, pid, "iam:user:add", []string{api.URN()})

				_, _ = s.roleSvc.Create(ctx, domain.Role{
					Code: "OTHER_ROLE",
					InlinePolicies: []domain.Policy{
						{Statement: []domain.Statement{
							{Effect: domain.Allow, Action: []string{"other:resource"}, Resource: []string{"*"}},
						}},
					},
				})
				_, _ = s.permSvc.AssignRoleToUser(ctx, s.testUid, "OTHER_ROLE")
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "场景3: 用户拥有正确权限 -> 预期 200",
			before: func(ctx context.Context, tid int64) {
				s.testUid = 1003
				api := domain.API{Service: "iam", Method: "POST", Path: "/api/user/add"}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)
				pid, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "iam:user:add"})
				_ = s.permSvc.BindResourcesToPermission(ctx, pid, "iam:user:add", []string{api.URN()})

				_, _ = s.roleSvc.Create(ctx, domain.Role{
					Code: "IAM_ADMIN",
					InlinePolicies: []domain.Policy{
						{Statement: []domain.Statement{
							{Effect: domain.Allow, Action: []string{"iam:user:add"}, Resource: []string{"*"}},
						}},
					},
				})
				_, _ = s.permSvc.AssignRoleToUser(ctx, s.testUid, "IAM_ADMIN")
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			// NOTE: 使用 defer 确保在每个子测试逻辑结束后执行清理，这是最简单且可靠的“结束后清理”方案
			defer s.clearAll()

			s.ensureAdminRole(context.Background())
			tid, err := s.tenantSvc.CreateTenant(context.Background(), "测试用例", "test888", 9999)
			require.NoError(s.T(), err)
			s.testTid = tid
			ctx := ctxutil.WithTenantID(context.Background(), tid)

			if tc.before != nil {
				tc.before(ctx, tid)
			}

			req := httptest.NewRequest("POST", "/api/user/add", nil)
			req.Header.Set("x-tenant-id", fmt.Sprintf("%d", tid))
			w := httptest.NewRecorder()

			s.server.ServeHTTP(w, req)
			require.Equal(s.T(), tc.wantCode, w.Code)
		})
	}
}

func TestHandlerAuthTestSuite(t *testing.T) {
	suite.Run(t, new(HandlerAuthTestSuite))
}
