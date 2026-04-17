package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/policy"
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

type PolicyTestSuite struct {
	suite.Suite

	db       *gorm.DB
	enforcer *casbin.SyncedEnforcer
	ctrl     *gomock.Controller

	permSvc     permission.IPermissionService
	tenantSvc   tenant.ITenantService
	roleSvc     role.IRoleService
	policySvc   policy.IPolicyService
	resourceSvc resource.IResourceService
}

func (s *PolicyTestSuite) SetupSuite() {
	dir, _ := os.Getwd()
	viper.SetConfigFile(filepath.Join(dir, "../config/config.yaml"))
	_ = viper.ReadInConfig()

	deps, err := testioc.InitPermissionSuiteDeps()
	s.Require().NoError(err)

	s.db = deps.DB
	s.enforcer = deps.Enforcer
	s.permSvc = deps.PermSvc
	s.tenantSvc = deps.TenantSvc
	s.roleSvc = deps.RoleSvc
	s.policySvc = deps.PolicySvc
	s.resourceSvc = deps.ResourceSvc
}

func (s *PolicyTestSuite) TearDownTest() {
	s.clearAll()
}

func (s *PolicyTestSuite) clearAll() {
	s.db.Exec("DELETE FROM `tenant`")
	s.db.Exec("DELETE FROM `role`")
	s.db.Exec("DELETE FROM `policy`")
	s.db.Exec("DELETE FROM `policy_assignment`")
	s.db.Exec("DELETE FROM `casbin_rule`")
}

// ensureAdminRole 确保系统中存在基础角色，支持租户创建等后续业务
func (s *PolicyTestSuite) ensureAdminRole(ctx context.Context) {
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
	_, _ = s.roleSvc.Create(ctx, domain.Role{
		Code: "admin",
		Name: "租户管理员",
	})
	_, _ = s.permSvc.AssignRoleInheritance(ctx, "admin", "super_admin")
}

func (s *PolicyTestSuite) TestManagedPolicyAuthorization() {
	// 在父函数中定义基础数据，但在子测试中按需初始化或直接运行
	// 为了避免 TearDownSubTest 的干扰，我们在本 Suite 中不定义 TearDownSubTest
	// 只在 TearDownTest (每个顶级 Test 方法结束) 后清理一次

	ctx := context.Background()
	s.ensureAdminRole(ctx)
	tid, err := s.tenantSvc.CreateTenant(ctx, "策略测试租户", "policy-test", "admin_tester", 1001)
	s.Require().NoError(err)
	ctx = ctxutil.WithTenantID(ctx, tid)

	// 1. 创建一个托管策略：允许查看账单
	policyCode := "p:finance:billing-view"
	_, err = s.policySvc.CreatePolicy(ctx, domain.Policy{
		Code: policyCode,
		Name: "财务账单查看策略",
		Type: domain.SystemPolicy,
		Statement: []domain.Statement{
			{Effect: domain.Allow, Action: []string{"finance:billing:view"}, Resource: []string{"*"}},
		},
	})
	s.Require().NoError(err)

	// 2. 创建角色
	role1 := "finance_staff"
	role2 := "finance_manager"
	_, _ = s.roleSvc.Create(ctx, domain.Role{Code: role1, Name: "财务专员"})
	_, _ = s.roleSvc.Create(ctx, domain.Role{Code: role2, Name: "财务主管"})

	// 3. 将托管策略挂载到这两个角色上
	_ = s.policySvc.AttachPolicyToRole(ctx, role1, policyCode)
	_ = s.policySvc.AttachPolicyToRole(ctx, role2, policyCode)

	// 4. 给主管增加额外的内联策略
	_ = s.roleSvc.UpdateInlinePolicies(ctx, role2, []domain.Policy{
		{
			Code: "billing_delete_policy",
			Statement: []domain.Statement{
				{Effect: domain.Allow, Action: []string{"finance:billing:delete"}, Resource: []string{"*"}},
			},
		},
	})

	testcases := []struct {
		name     string
		userId   int64
		role     string
		action   string
		resource string
		want     bool
	}{
		{
			name:     "专员拥有托管策略权限",
			userId:   2001,
			role:     role1,
			action:   "finance:billing:view",
			resource: "*",
			want:     true,
		},
		{
			name:     "主管拥有托管策略权限 (共享托管策略)",
			userId:   2002,
			role:     role2,
			action:   "finance:billing:view",
			resource: "*",
			want:     true,
		},
		{
			name:     "主管拥有特有的内联策略权限",
			userId:   2002,
			role:     role2,
			action:   "finance:billing:delete",
			resource: "*",
			want:     true,
		},
		{
			name:     "专员没有主管的内联权限",
			userId:   2001,
			role:     role1,
			action:   "finance:billing:delete",
			resource: "*",
			want:     false,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			// 在 Casbin 中分配角色
			_, _ = s.permSvc.AssignRoleToUser(ctx, fmt.Sprintf("user_%d", tc.userId), tc.role)

			// 执行鉴权判定
			allowed, err := s.permSvc.CheckPermission(ctx, fmt.Sprintf("user_%d", tc.userId), tc.action, tc.resource)
			s.Require().NoError(err)
			s.Equal(tc.want, allowed)
		})
	}
}

func TestPolicySuite(t *testing.T) {
	suite.Run(t, new(PolicyTestSuite))
}
