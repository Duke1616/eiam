package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/service/permission"
	policysvc "github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/internal/service/tenant"
	testioc "github.com/Duke1616/eiam/internal/test/ioc"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/casbin/casbin/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"
)

type MultiTenancySuite struct {
	suite.Suite

	db       *gorm.DB
	enforcer *casbin.SyncedEnforcer
	ctrl     *gomock.Controller

	permSvc     permission.IPermissionService
	tenantSvc   tenant.ITenantService
	roleSvc     role.IRoleService
	policySvc   policysvc.IPolicyService
	resourceSvc resource.IResourceService
}

func (s *MultiTenancySuite) SetupSuite() {
	dir, _ := os.Getwd()
	viper.SetConfigFile(filepath.Join(dir, "../config/config.yaml"))
	_ = viper.ReadInConfig()

	deps, _ := testioc.InitPermissionSuiteDeps()
	s.db = deps.DB
	s.enforcer = deps.Enforcer
	s.permSvc = deps.PermSvc
	s.tenantSvc = deps.TenantSvc
	s.roleSvc = deps.RoleSvc
	s.policySvc = deps.PolicySvc
	s.resourceSvc = deps.ResourceSvc
	s.ctrl = gomock.NewController(s.T())
}

func (s *MultiTenancySuite) TearDownTest() {
	s.clearAll()
}

func (s *MultiTenancySuite) clearAll() {
	s.db.Exec("DELETE FROM `tenant`")
	s.db.Exec("DELETE FROM `role`")
	s.db.Exec("DELETE FROM `policy`")
	s.db.Exec("DELETE FROM `policy_assignment`")
	s.db.Exec("DELETE FROM `api`")
	s.db.Exec("DELETE FROM `permission`")
	s.db.Exec("DELETE FROM `casbin_rule`")
}

// prepareSystemRoles 初始化系统预设环境 (TID=1)
func (s *MultiTenancySuite) prepareSystemRoles(ctx context.Context) {
	sysCtx := ctxutil.WithTenantID(ctx, ctxutil.SystemTenantID)

	// 全局管理员角色 (穿透型)
	_, _ = s.roleSvc.Create(sysCtx, domain.Role{
		Code: "super_admin",
		Type: domain.RoleTypeSystem,
		InlinePolicies: []domain.Policy{
			{
				Code:      "sys:allow_all",
				Statement: []domain.Statement{{Effect: domain.Allow, Action: []string{"*"}, Resource: []string{"*"}}},
			},
		},
	})
	_, _ = s.roleSvc.Create(sysCtx, domain.Role{Code: "admin", Type: domain.RoleTypeSystem})
	_, _ = s.permSvc.AddRoleInheritance(sysCtx, "admin", "super_admin")

	// 全局共享策略
	_, _ = s.policySvc.CreatePolicy(sysCtx, domain.Policy{
		Code: "sys_shared_read",
		Type: domain.SystemPolicy,
		Statement: []domain.Statement{
			{Effect: domain.Allow, Action: []string{"global:read"}, Resource: []string{"*"}},
		},
	})
}

func (s *MultiTenancySuite) TestCheckAPI_TenancyMatrix() {
	type request struct {
		username string
		service  string
		method   string
		path     string
	}

	testcases := []struct {
		name     string
		setup    func(ctx context.Context) context.Context // 返回测试执行时的 Context
		request  request
		wantAllowed bool
	}{
		{
			name: "业务租户管理员继承系统角色：应获得全量授权",
			setup: func(ctx context.Context) context.Context {
				// 创建租户 A (tid=2)
				tid, _ := s.tenantSvc.CreateTenant(ctx, "租户A", "t-a", "admin_a", 1)
				tCtx := ctxutil.WithTenantID(ctx, tid)

				// 1. 准备私有 API
				api := domain.API{Service: "svc", Method: "GET", Path: "/private"}
				_, _ = s.resourceSvc.CreateAPI(tCtx, api)

				// 2. 准备权限项并绑定 API (这是 CheckAPI 能识别 API 的前提)
				pid, _ := s.permSvc.CreatePermission(tCtx, domain.Permission{Code: "ta:private:view"})
				_ = s.permSvc.BindResourcesToPermission(tCtx, pid, "ta:private:view", []string{api.URN()})

				// 3. 绑定租户 1 的系统角色
				_, _ = s.permSvc.AssignRoleToUser(tCtx, "admin_a", "admin")
				return tCtx
			},
			request: request{"admin_a", "svc", "GET", "/private"},
			wantAllowed: true,
		},
		{
			name: "租户隔离校验：租户 B 用户无法访问租户 A 的私有资源",
			setup: func(ctx context.Context) context.Context {
				tidA, _ := s.tenantSvc.CreateTenant(ctx, "租户A", "t-a", "user_a", 1)
				tidB, _ := s.tenantSvc.CreateTenant(ctx, "租户B", "t-b", "user_b", 2)
				ctxA := ctxutil.WithTenantID(ctx, tidA)
				ctxB := ctxutil.WithTenantID(ctx, tidB)

				// A 租户创建私有资源并授权
				api := domain.API{Service: "svc", Method: "POST", Path: "/secret"}
				_, _ = s.resourceSvc.CreateAPI(ctxA, api)
				pid, _ := s.permSvc.CreatePermission(ctxA, domain.Permission{Code: "perm:a"})
				_ = s.permSvc.BindResourcesToPermission(ctxA, pid, "perm:a", []string{api.URN()})

				_, _ = s.roleSvc.Create(ctxA, domain.Role{Code: "role_a"})
				_ = s.permSvc.AssignPolicyToRole(ctxA, "role_a", "sys_shared_read") // 借用系统策略
				_, _ = s.permSvc.AssignRoleToUser(ctxA, "user_a", "role_a")

				return ctxB // 返回租户 B 的上下文进行测试
			},
			request: request{"user_b", "svc", "POST", "/secret"},
			wantAllowed: false,
		},
		{
			name: "全局策略应用：业务租户绑定系统策略后应获得授权",
			setup: func(ctx context.Context) context.Context {
				sysCtx := ctxutil.WithTenantID(ctx, ctxutil.SystemTenantID)
				tidA, _ := s.tenantSvc.CreateTenant(ctx, "租户A", "t-a", "user_a", 1)
				tCtx := ctxutil.WithTenantID(ctx, tidA)

				// 系统租户定义 API 和 权限项
				api := domain.API{Service: "svc", Method: "GET", Path: "/global"}
				_, _ = s.resourceSvc.CreateAPI(sysCtx, api)
				pid, _ := s.permSvc.CreatePermission(sysCtx, domain.Permission{Code: "global:read"})
				_ = s.permSvc.BindResourcesToPermission(sysCtx, pid, "global:read", []string{api.URN()})

				// 租户 A 角色绑定系统策略 "sys_shared_read" (该策略已在 prepareSystemRoles 创建)
				_, _ = s.roleSvc.Create(tCtx, domain.Role{Code: "r_a"})
				_ = s.permSvc.AssignPolicyToRole(tCtx, "r_a", "sys_shared_read")
				_, _ = s.permSvc.AssignRoleToUser(tCtx, "u_a", "r_a")

				return tCtx
			},
			request: request{"u_a", "svc", "GET", "/global"},
			wantAllowed: true,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			s.clearAll()
			s.prepareSystemRoles(context.Background())

			// 1. Setup
			execCtx := tc.setup(context.Background())

			// 2. Execute
			ok, err := s.permSvc.CheckAPI(execCtx, tc.request.username, tc.request.service, tc.request.method, tc.request.path)

			// 3. Verify
			s.NoError(err)
			s.Equal(tc.wantAllowed, ok, "鉴权结果不符合预期")
		})
	}
}

func TestMultiTenancy(t *testing.T) {
	suite.Run(t, new(MultiTenancySuite))
}
