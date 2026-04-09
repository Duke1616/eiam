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
	"gorm.io/gorm"
)

// PermissionSuite 集成测试套件
type PermissionSuite struct {
	suite.Suite
	db       *gorm.DB
	enforcer *casbin.SyncedEnforcer

	tenantSvc   tenant.ITenantService
	roleSvc     role.IRoleService
	resourceSvc resource.IResourceService
	permSvc     permission.IPermissionService
}

func (s *PermissionSuite) SetupSuite() {
	dir, _ := os.Getwd()
	viper.SetConfigFile(filepath.Join(dir, "../config/config.yaml"))
	err := viper.ReadInConfig()
	require.NoError(s.T(), err)

	deps, err := testioc.InitPermissionSuiteDeps()
	require.NoError(s.T(), err)

	s.db = deps.DB
	s.enforcer = deps.Enforcer
	s.tenantSvc = deps.TenantSvc
	s.roleSvc = deps.RoleSvc
	s.resourceSvc = deps.ResourceSvc
	s.permSvc = deps.PermSvc
}

func (s *PermissionSuite) TearDownSubTest() {
	s.clearAll()
}

func (s *PermissionSuite) clearAll() {
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

func (s *PermissionSuite) TestCheckAPI() {
	serviceName := "cmdb"
	path := "/api/v1/hosts"
	method := "GET"
	actionCode := "cmdb:host:view"

	testcases := []struct {
		name   string
		before func(ctx context.Context, tid int64)
		run    func(ctx context.Context, tid int64) // 支持自定义运行逻辑，方便测试跨租户
	}{
		{
			name: "场景1: ADMIN 用户请求已授权的 API 应通过",
			before: func(ctx context.Context, tid int64) {
				_, _ = s.permSvc.AssignRoleToUser(ctx, 8888, "ADMIN")
				api := domain.API{Service: serviceName, Path: path, Method: method}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)
				permId, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: actionCode})
				_ = s.permSvc.BindResourcesToPermission(ctx, permId, actionCode, []string{api.URN()})
			},
			run: func(ctx context.Context, tid int64) {
				ok, err := s.permSvc.CheckAPI(ctx, 8888, serviceName, method, path)
				require.NoError(s.T(), err)
				assert.True(s.T(), ok)
			},
		},
		{
			name: "场景2: DEVELOPER 角色请求已授权 API 应通过",
			before: func(ctx context.Context, tid int64) {
				_, _ = s.roleSvc.Create(ctx, domain.Role{Code: "DEVELOPER", Name: "开发", TenantID: tid})
				_ = s.roleSvc.UpdatePolicies(ctx, "DEVELOPER", []domain.Policy{{
					Type:      domain.CustomPolicy,
					Statement: []domain.Statement{{Effect: domain.Allow, Resource: []string{"*"}, Action: []string{actionCode}}},
				}})
				_, _ = s.permSvc.AssignRoleToUser(ctx, 6666, "DEVELOPER")
				api := domain.API{Service: serviceName, Path: path, Method: method}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)
				permId, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: actionCode})
				_ = s.permSvc.BindResourcesToPermission(ctx, permId, actionCode, []string{api.URN()})
			},
			run: func(ctx context.Context, tid int64) {
				ok, err := s.permSvc.CheckAPI(ctx, 6666, serviceName, method, path)
				require.NoError(s.T(), err)
				assert.True(s.T(), ok)
			},
		},
		{
			name: "场景3: 多租户隔离拦截跨租户请求",
			before: func(ctx context.Context, tid int64) {
				// 1. 在租户 A 下注册 API 并授权
				api := domain.API{Service: serviceName, Path: path, Method: method}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)
				permId, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "view"})
				_ = s.permSvc.BindResourcesToPermission(ctx, permId, "view", []string{api.URN()})

				_, _ = s.roleSvc.Create(ctx, domain.Role{Code: "VIEWER", TenantID: tid})
				_ = s.roleSvc.UpdatePolicies(ctx, "VIEWER", []domain.Policy{{
					Type:      domain.CustomPolicy,
					Statement: []domain.Statement{{Effect: domain.Allow, Action: []string{"view"}, Resource: []string{"*"}}},
				}})
				_, _ = s.permSvc.AssignRoleToUser(ctx, 8888, "VIEWER")
			},
			run: func(ctx context.Context, tid int64) {
				// 2. 模拟切换至租户 B 的上下文进行请求
				shadowTid := int64(9991)
				shadowCtx := ctxutil.WithTenantID(context.Background(), shadowTid)

				ok, err := s.permSvc.CheckAPI(shadowCtx, 8888, serviceName, method, path)
				assert.NoError(s.T(), err)
				assert.False(s.T(), ok, "跨租户请求应被拦截")
			},
		},
		{
			name: "场景4: Fail-closed 拦截未注册资产",
			before: func(ctx context.Context, tid int64) {
				_, _ = s.permSvc.AssignRoleToUser(ctx, 8888, "SUPER_ADMIN")
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
