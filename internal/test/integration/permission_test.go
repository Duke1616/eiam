package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
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

// PermissionSuite 集成测试套件，模仿真实的业务环境注入
// 用于对齐你在混合权限模型测试中的断言习惯
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
	// 1. 初始化运行配置项
	dir, _ := os.Getwd()
	viper.SetConfigFile(filepath.Join(dir, "../config/config.yaml"))
	err := viper.ReadInConfig()
	require.NoError(s.T(), err, "请确保能在当前目录的上两级找到 config/config.yaml")

	// 2. 利用 test ioc 一键启动核心组件及微服务依赖
	deps, err := testioc.InitPermissionSuiteDeps()
	require.NoError(s.T(), err, "依赖注入初始化失败")

	s.db = deps.DB
	s.enforcer = deps.Enforcer
	s.tenantSvc = deps.TenantSvc
	s.roleSvc = deps.RoleSvc
	s.resourceSvc = deps.ResourceSvc
	s.permSvc = deps.PermSvc
}

func (s *PermissionSuite) clearAll() {
	// 清理测试环境遗留数据，确保隔离
	t := s.T()
	t.Helper()

	// 注意：执行此清库操作时，请确保配置的是 【测试数据库】。
	s.db.Exec("TRUNCATE TABLE casbin_rule")
	s.db.Exec("TRUNCATE TABLE permission")
	s.db.Exec("TRUNCATE TABLE permission_binding")
	s.db.Exec("TRUNCATE TABLE role")
	s.db.Exec("TRUNCATE TABLE tenant")
	s.db.Exec("TRUNCATE TABLE membership")
	s.db.Exec("TRUNCATE TABLE api")
}

// TestCheckAPI 集成测试核心路：由 URL -> Code -> Role -> User 的联动
func (s *PermissionSuite) TestCheckAPI() {
	t := s.T()

	// 执行完成后清理测试数据
	defer s.clearAll()

	var (
		userId      int64 = 8888
		serviceName       = "cmdb"
		path              = "/api/v1/hosts"
		method            = "GET"
		actionCode        = "cmdb:host:view"
	)

	// ==================== 一、 场景准备期 ====================

	// 0. 我们先在数据库底层预置全系统的基础角色 (TenantID = 0, Type = System)
	sysCtx := ctxutil.WithTenantID(context.Background(), 0)
	_, err := s.roleSvc.Create(sysCtx, domain.Role{Code: "OWNER", Name: "系统内置租户拥有者", Type: domain.RoleTypeSystem, TenantID: 0})
	require.NoError(t, err)

	// 赋予预置角色 '*' 的天花板策略 (一次配置，全系统租户共用)
	err = s.roleSvc.UpdatePolicies(sysCtx, "OWNER", []domain.Policy{
		{
			Name: "内置最高权限策略",
			Type: domain.SystemPolicy,
			Statement: []domain.Statement{{Effect: domain.Allow, Resource: []string{"*"}, Action: []string{"*"}}},
		},
	})
	require.NoError(t, err)

	// 1. 初始化主租户，会自动将 UserId=8888 绑定为预设好系统级的 OWNER 角色
	tenantId, err := s.tenantSvc.CreateTenant(context.Background(), "测试机房", "test-room", userId)
	require.NoError(t, err)

	ctxWithTenant := ctxutil.WithTenantID(context.Background(), tenantId)

	// 2. 模拟部署 cmdb 微服务，注册其对外的 API
	resApiId, err := s.resourceSvc.CreateAPI(ctxWithTenant, domain.API{
		Service: serviceName,
		Path:    path,
		Method:  method,
		Name:    "查看主机列表",
	})
	require.NoError(t, err)

	// 3. 将物理 API 关联给一个抽象能力码 `cmdb:host:view`
	permId, err := s.permSvc.CreatePermission(ctxWithTenant, domain.Permission{
		Code: actionCode,
		Name: "主机查看权",
	})
	require.NoError(t, err)

	err = s.permSvc.BindResourcesToPermission(ctxWithTenant, permId, actionCode, domain.ResourceTypeAPI, []int64{resApiId})
	require.NoError(t, err)

	// 4. (已删除) 原本在此处给单租户的 OWNER 单独硬写入策略，现在改成了在顶部(步骤 0)统一配置全局的系统角色。

	// ----------------- 复杂混合场景追加 -----------------
	var (
		devUserId   int64 = 6666 // 租户1下的受限开发人员
		crossUserId int64 = 7777 // 租户2的最高拥有者
	)

	// 5. 租户1：精细化角色设定 - 给 DEVELOPER 定制只读策略
	_, err = s.roleSvc.Create(ctxWithTenant, domain.Role{Code: "DEVELOPER", Name: "开发人员", Desc: "限制性的只读权限", TenantID: tenantId})
	require.NoError(t, err)

	err = s.roleSvc.UpdatePolicies(ctxWithTenant, "DEVELOPER", []domain.Policy{
		{
			Name: "安全只读约束",
			Type: domain.CustomPolicy,
			Statement: []domain.Statement{
				{
					Effect:   domain.Allow,
					Resource: []string{"*"},
					Action:   []string{actionCode}, // 仅仅赋予 cmdb:host:view
				},
			},
		},
	})
	require.NoError(t, err)

	// 5.1 绑定角色与用户
	_, err = s.permSvc.AssignRoleToUser(ctxWithTenant, devUserId, "DEVELOPER")
	require.NoError(t, err)

	// 6. 租户1：增加一条删除命令 (DELETE)，验证已注册但未授权的拦截情况
	resApiIdDel, err := s.resourceSvc.CreateAPI(ctxWithTenant, domain.API{
		Service: serviceName,
		Path:    path,
		Method:  "DELETE",
		Name:    "删除主机",
	})
	require.NoError(t, err)
	permIdDel, err := s.permSvc.CreatePermission(ctxWithTenant, domain.Permission{
		Code: "cmdb:host:delete",
		Name: "主机删除权限",
	})
	require.NoError(t, err)
	err = s.permSvc.BindResourcesToPermission(ctxWithTenant, permIdDel, "cmdb:host:delete", domain.ResourceTypeAPI, []int64{resApiIdDel})
	require.NoError(t, err)

	// 7. 建立另一个正常的租户 (租户2) 用于测试多租户隔离
	tenantId2, err := s.tenantSvc.CreateTenant(context.Background(), "生产机房", "prod-room", crossUserId)
	require.NoError(t, err)

	// 8. 多 code 绑定同一 API 场景测试准备：
	// 给原有的 GET /api/v1/hosts 追加绑定一个新能力码：'cmdb:dashboard:view'
	permIdDash, err := s.permSvc.CreatePermission(ctxWithTenant, domain.Permission{
		Code: "cmdb:dashboard:view",
		Name: "大盘查看权",
	})
	require.NoError(t, err)
	err = s.permSvc.BindResourcesToPermission(ctxWithTenant, permIdDash, "cmdb:dashboard:view", domain.ResourceTypeAPI, []int64{resApiId})
	require.NoError(t, err)

	// 给一个新用户赋予仅仅看大盘的权利
	var dashboardUserId int64 = 5555
	_, err = s.roleSvc.Create(ctxWithTenant, domain.Role{Code: "DASHBOARD_VIEWER", Name: "数据大盘查看者", TenantID: tenantId})
	require.NoError(t, err)
	err = s.roleSvc.UpdatePolicies(ctxWithTenant, "DASHBOARD_VIEWER", []domain.Policy{
		{
			Name: "大盘只读",
			Type: domain.CustomPolicy,
			Statement: []domain.Statement{{Effect: domain.Allow, Resource: []string{"*"}, Action: []string{"cmdb:dashboard:view"}}},
		},
	})
	require.NoError(t, err)
	_, err = s.permSvc.AssignRoleToUser(ctxWithTenant, dashboardUserId, "DASHBOARD_VIEWER")
	require.NoError(t, err)

	// 9. Casbin 角色继承测试 (RBAC with Domains)
	// 创建一个上层 ADMIN 角色，什么具体策略都不配置
	var adminUserId int64 = 4444
	_, err = s.roleSvc.Create(ctxWithTenant, domain.Role{Code: "ADMIN", Name: "部门管理员", TenantID: tenantId})
	require.NoError(t, err)

	// 核心：让 ADMIN 继承 DEVELOPER 的所有能力
	_, err = s.permSvc.AssignRoleInheritance(ctxWithTenant, "ADMIN", "DEVELOPER")
	require.NoError(t, err)

	// 把新员工 4444 分配为 ADMIN 角色 (他仅有 ADMIN)
	_, err = s.permSvc.AssignRoleToUser(ctxWithTenant, adminUserId, "ADMIN")
	require.NoError(t, err)

	// ==================== 二、 断言执行期 ====================
	testcases := []struct {
		name    string
		uid     int64
		service string
		method  string
		path    string
		tenant  int64
		want    bool // 预期是否允许运行
	}{
		{
			name:    "OWNER 用户请求已授权的 API 应通过",
			uid:     userId,
			service: serviceName,
			method:  method,
			path:    path,
			tenant:  tenantId,
			want:    true,
		},
		{
			name:    "OWNER 用户请求未直接关联但匹配全局通配符 '*' 的 API 应通过",
			uid:     userId,
			service: serviceName,
			method:  "DELETE",
			path:    path,
			tenant:  tenantId,
			want:    true,
		},
		{
			name:    "无角色用户请求注册的 API 应被拦截",
			uid:     9999,
			service: serviceName,
			method:  method,
			path:    path,
			tenant:  tenantId,
			want:    false,
		},
		{
			name:    "DEVELOPER 角色请求已授权 API 应通过",
			uid:     devUserId,
			service: serviceName,
			method:  method,
			path:    path,
			tenant:  tenantId,
			want:    true,
		},
		{
			name:    "DEVELOPER 角色请求已注册但未被授权的 API 应被拦截",
			uid:     devUserId,
			service: serviceName,
			method:  "DELETE",
			path:    path,
			tenant:  tenantId,
			want:    false,
		},
		{
			name:    "多租户隔离约束下的跨租户请求，租户 1 的 OWNER 访问租户 2 资源应被拦截",
			uid:     userId,
			service: serviceName,
			method:  method,
			path:    path,
			tenant:  tenantId2,
			want:    false,
		},
		{
			name:    "任意用户请求完全未注册的 API，应当触发 Fail-closed 拦截",
			uid:     userId,
			service: serviceName,
			method:  "PUT",
			path:    path,
			tenant:  tenantId,
			want:    false,
		},
		{
			name:    "多 Code 绑定测试：只有大盘查看权的用户，请求被多重绑定的同一 API 应通过",
			uid:     dashboardUserId,
			service: serviceName,
			method:  method,
			path:    path,
			tenant:  tenantId,
			want:    true,
		},
		{
			name:    "RBAC 层级继承测试：ADMIN 本身未分配该策略，但因继承自 DEVELOPER，请求查列表应通过",
			uid:     adminUserId,
			service: serviceName,
			method:  method,
			path:    path,
			tenant:  tenantId,
			want:    true,
		},
		{
			name:    "RBAC 层级继承阻断测试：强如 ADMIN 也没有被赋予删除权限 (因为他爹 DEVELOPER 也没有)，应被拦截",
			uid:     adminUserId,
			service: serviceName,
			method:  "DELETE",
			path:    path,
			tenant:  tenantId,
			want:    false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			checkCtx := ctxutil.WithTenantID(context.Background(), tc.tenant)
			pass, err := s.permSvc.CheckAPI(checkCtx, tc.uid, tc.service, tc.method, tc.path)

			// 如果我们期望 true，那么整个链条绝不能抛出 error（比如没找到实体等）
			if tc.want {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, pass)
		})
	}
}

// 统一执行套件入口
func TestPermissionSuite(t *testing.T) {
	suite.Run(t, new(PermissionSuite))
}
