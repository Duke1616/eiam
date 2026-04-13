package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/internal/service/tenant"
	testioc "github.com/Duke1616/eiam/internal/test/ioc"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/casbin/casbin/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"
)

type PermissionSuite struct {
	suite.Suite

	db       *gorm.DB
	enforcer *casbin.SyncedEnforcer
	ctrl     *gomock.Controller

	permSvc     permission.IPermissionService
	tenantSvc   tenant.ITenantService
	roleSvc     role.IRoleService
	resourceSvc resource.IResourceService

	testUid int64
}

func (s *PermissionSuite) SetupSuite() {
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
	s.roleSvc = deps.RoleSvc
	s.resourceSvc = deps.ResourceSvc
	s.ctrl = gomock.NewController(s.T())
}

func (s *PermissionSuite) TearDownTest() {
	s.clearAll()
}

func (s *PermissionSuite) TearDownSubTest() {
	s.clearAll()
}

func (s *PermissionSuite) clearAll() {
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

// ensureAdminRole 确保环境中存在基础的 admin 角色记录，以支持 CreateTenant 等业务链条
func (s *PermissionSuite) ensureAdminRole(ctx context.Context) {
	// 1. 创建全局超级管理员 (赋予全量 Allow)
	_, _ = s.roleSvc.Create(ctx, domain.Role{
		Code: "super_admin",
		Name: "全量管理员",
		InlinePolicies: []domain.Policy{
			{
				Code:      "root_allow_all",
				Statement: []domain.Statement{{Effect: domain.Allow, Action: []string{"*"}, Resource: []string{"*"}}},
			},
		},
	})
	// 2. 创建租户管理员 (通过继承获得能力)
	_, _ = s.roleSvc.Create(ctx, domain.Role{
		Code: "admin",
		Name: "租户管理员",
	})

	// 3. 建立 Casbin 层面的继承关系 (admin 继承 super_admin)
	_, _ = s.permSvc.AssignRoleInheritance(ctx, "admin", "super_admin")
}

func (s *PermissionSuite) TestCheckAPI() {
	serviceName := "user-service"

	testcases := []struct {
		name   string
		before func(ctx context.Context, tid int64)
		run    func(ctx context.Context, tid int64)
	}{
		{
			name: "场景1: ADMIN 用户请求已授权的 API 应通过",
			before: func(ctx context.Context, tid int64) {
				api := domain.API{Service: serviceName, Method: "GET", Path: "/api/v1/users"}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)
				pid, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "iam:user:view"})
				_ = s.permSvc.BindResourcesToPermission(ctx, pid, "iam:user:view", []string{api.URN()})

				// 分配角色 (由于 CreateTenant 时系统已自动分配过一次，此处主要确保 Casbin 策略完整)
				_, _ = s.permSvc.AssignRoleToUser(ctx, 12345, "admin")
			},
			run: func(ctx context.Context, tid int64) {
				ok, err := s.permSvc.CheckAPI(ctx, 12345, serviceName, "GET", "/api/v1/users")
				assert.NoError(s.T(), err)
				assert.True(s.T(), ok)
			},
		},
		{
			name: "场景2: DEVELOPER 角色请求已授权 API 应通过",
			before: func(ctx context.Context, tid int64) {
				api := domain.API{Service: serviceName, Method: "GET", Path: "/api/v1/users"}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)
				pid, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "iam:user:view"})
				_ = s.permSvc.BindResourcesToPermission(ctx, pid, "iam:user:view", []string{api.URN()})

				_, _ = s.roleSvc.Create(ctx, domain.Role{
					Code: "DEVELOPER",
					InlinePolicies: []domain.Policy{
						{Statement: []domain.Statement{
							{Effect: domain.Allow, Action: []string{"iam:user:view"}, Resource: []string{"*"}},
						}},
					},
				})
				_, _ = s.permSvc.AssignRoleToUser(ctx, 2222, "DEVELOPER")
			},
			run: func(ctx context.Context, tid int64) {
				ok, err := s.permSvc.CheckAPI(ctx, 2222, serviceName, "GET", "/api/v1/users")
				assert.NoError(s.T(), err)
				assert.True(s.T(), ok)
			},
		},
		{
			name: "场景3: 多租户隔离拦截跨租户请求",
			before: func(ctx context.Context, tid int64) {
				api := domain.API{Service: serviceName, Method: "GET", Path: "/api/v1/users"}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)

				otherTid, _ := s.tenantSvc.CreateTenant(context.Background(), "黑客空间", "hacker", 999)
				otherCtx := ctxutil.WithTenantID(context.Background(), otherTid)
				_, _ = s.roleSvc.Create(otherCtx, domain.Role{Code: "DEV_HACKER"})
				_, _ = s.permSvc.AssignRoleToUser(otherCtx, 999, "DEV_HACKER")
			},
			run: func(ctx context.Context, tid int64) {
				ok, err := s.permSvc.CheckAPI(ctx, 999, serviceName, "GET", "/api/v1/users")
				assert.NoError(s.T(), err)
				assert.False(s.T(), ok)
			},
		},
		{
			name: "场景4: Fail-closed 拦截未注册资产",
			before: func(ctx context.Context, tid int64) {
				_, _ = s.permSvc.AssignRoleToUser(ctx, 8888, "super_admin")
			},
			run: func(ctx context.Context, tid int64) {
				ok, err := s.permSvc.CheckAPI(ctx, 8888, serviceName, "POST", "/unknown")
				assert.NoError(s.T(), err)
				assert.False(s.T(), ok)
			},
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			defer s.clearAll()
			// 在调用 CreateTenant 之前，必须确保物理层存在 ADMIN/SUPER_ADMIN 角色条目
			s.ensureAdminRole(context.Background())

			tid, err := s.tenantSvc.CreateTenant(context.Background(), "测试用例", "test", 8888)
			require.NoError(s.T(), err)
			ctx := ctxutil.WithTenantID(context.Background(), tid)

			if tc.before != nil {
				tc.before(ctx, tid)
			}
			if tc.run != nil {
				tc.run(ctx, tid)
			}
		})
	}
}

func (s *PermissionSuite) TestRoleCycleDetection() {
	s.clearAll()
	s.ensureAdminRole(context.Background())

	tid, err := s.tenantSvc.CreateTenant(context.Background(), "循环测试", "cycle", 1)
	require.NoError(s.T(), err)
	ctx := ctxutil.WithTenantID(context.Background(), tid)

	_, _ = s.roleSvc.Create(ctx, domain.Role{Code: "A"})
	_, _ = s.roleSvc.Create(ctx, domain.Role{Code: "B"})

	_, _ = s.permSvc.AssignRoleInheritance(ctx, "A", "B")
	ok, err := s.permSvc.AssignRoleInheritance(ctx, "B", "A")

	assert.ErrorIs(s.T(), err, errs.ErrRoleCycleInheritance)
	assert.False(s.T(), ok)
}

func TestPermissionSuite(t *testing.T) {
	suite.Run(t, new(PermissionSuite))
}
