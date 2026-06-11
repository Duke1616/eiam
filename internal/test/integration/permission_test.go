package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/resource/ingestion"
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
	s.db.Exec("DELETE FROM `policy_assignment`")
	s.db.Exec("DELETE FROM `api`")
	s.db.Exec("DELETE FROM `permission`")
	s.db.Exec("DELETE FROM `permission_binding`")
	s.db.Exec("DELETE FROM `casbin_rule`")
	s.db.Exec("DELETE FROM `menu`")
}

// ensureAdminRole 确保环境中存在基础的 admin 角色记录，以支持 CreateTenant 等业务链条
func (s *PermissionSuite) ensureAdminRole(ctx context.Context) {
	// 强制将系统角色的创建域设置为 SystemTenantID，确保全系统可见
	sysCtx := ctxutil.WithTenantID(ctx, ctxutil.SystemTenantID)

	// 1. 创建全局超级管理员 (赋予全量 Allow)
	_, _ = s.roleSvc.Create(sysCtx, domain.Role{
		Code: "super_admin",
		Name: "全量管理员",
		Type: domain.RoleTypeSystem,
		InlinePolicies: []domain.Policy{
			{
				Code:      "root_allow_all",
				Statement: []domain.Statement{{Effect: domain.Allow, Action: []string{"*"}, Resource: []string{"*"}}},
			},
		},
	})
	// 2. 创建租户管理员 (通过继承获得能力)
	_, _ = s.roleSvc.Create(sysCtx, domain.Role{
		Code: "admin",
		Name: "租户管理员",
		Type: domain.RoleTypeSystem,
	})

	// 3. 建立 Casbin 层面的继承关系 (admin 继承 super_admin)
	_, _ = s.permSvc.AddRoleInheritance(sysCtx, "admin", "super_admin")
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
				_, _ = s.permSvc.AssignRoleToUser(ctx, "admin_user", "admin")
			},
			run: func(ctx context.Context, tid int64) {
				ok, err := s.permSvc.CheckAPI(ctx, "admin_user", serviceName, "GET", "/api/v1/users")
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
				_, _ = s.permSvc.AssignRoleToUser(ctx, "dev_user", "DEVELOPER")
			},
			run: func(ctx context.Context, tid int64) {
				ok, err := s.permSvc.CheckAPI(ctx, "dev_user", serviceName, "GET", "/api/v1/users")
				assert.NoError(s.T(), err)
				assert.True(s.T(), ok)
			},
		},
		{
			name: "场景3: 多租户隔离拦截跨租户请求",
			before: func(ctx context.Context, tid int64) {
				api := domain.API{Service: serviceName, Method: "GET", Path: "/api/v1/users"}
				_, _ = s.resourceSvc.CreateAPI(ctx, api)
				pid, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "iam:user:view"})
				_ = s.permSvc.BindResourcesToPermission(ctx, pid, "iam:user:view", []string{api.URN()})

				otherTid, _ := s.tenantSvc.CreateTenant(context.Background(), "黑客空间", "hacker", "hacker_user", 999)
				otherCtx := ctxutil.WithTenantID(context.Background(), otherTid)
				_, _ = s.roleSvc.Create(otherCtx, domain.Role{Code: "DEV_HACKER"})
				_, _ = s.permSvc.AssignRoleToUser(otherCtx, "hacker_user", "DEV_HACKER")
			},
			run: func(ctx context.Context, tid int64) {
				ok, err := s.permSvc.CheckAPI(ctx, "hacker_user", serviceName, "GET", "/api/v1/users")
				assert.NoError(s.T(), err)
				assert.False(s.T(), ok)
			},
		},
		{
			name: "场景4: Fail-closed 拦截未注册资产",
			before: func(ctx context.Context, tid int64) {
				_, _ = s.permSvc.AssignRoleToUser(ctx, "super_user", "super_admin")
			},
			run: func(ctx context.Context, tid int64) {
				ok, err := s.permSvc.CheckAPI(ctx, "super_user", serviceName, "POST", "/unknown")
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

			tid, err := s.tenantSvc.CreateTenant(context.Background(), "测试用例", "test", "super_user", 8888)
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

	tid, err := s.tenantSvc.CreateTenant(context.Background(), "循环测试", "cycle", "admin", 1)
	require.NoError(s.T(), err)
	ctx := ctxutil.WithTenantID(context.Background(), tid)

	_, _ = s.roleSvc.Create(ctx, domain.Role{Code: "A"})
	_, _ = s.roleSvc.Create(ctx, domain.Role{Code: "B"})

	_, _ = s.permSvc.AddRoleInheritance(ctx, "A", "B")
	ok, err := s.permSvc.AddRoleInheritance(ctx, "B", "A")

	assert.ErrorIs(s.T(), err, errs.ErrRoleCycleInheritance)
	assert.False(s.T(), ok)
}

func (s *PermissionSuite) TestIngestPhysicalClearAndReload() {
	s.clearAll()

	// 1. 初始化 ingestion Engine
	permDAO := dao.NewPermissionDAO(s.db)
	resDAO := dao.NewResourceDAO(s.db)
	svcDAO := dao.NewServiceDAO(s.db)
	engine := ingestion.NewEngine(
		repository.NewPermissionRepository(permDAO),
		repository.NewResourceRepository(resDAO),
		repository.NewServiceRepository(svcDAO),
	)

	ctx := context.Background()
	service := "test_clean_svc"

	// 2. 构造第一次 Ingest Snap1
	snap1 := ingestion.Snapshot{
		Service: service,
		Permissions: []domain.Permission{
			{Code: "test:perm:p1", Name: "权限1", Group: "组1", Service: service},
		},
		APIs: []domain.API{
			{Service: service, Method: "GET", Path: "/api/v1/p1", Name: "接口1"},
		},
		Bindings: map[string][]string{
			"test:perm:p1": {"get:/api/v1/p1"},
		},
	}

	err := engine.Ingest(ctx, snap1)
	require.NoError(s.T(), err)

	// 验证第一次 Ingest 成功
	var countPerms int64
	s.db.Model(&dao.Permission{}).Where("service = ?", service).Count(&countPerms)
	assert.Equal(s.T(), int64(1), countPerms)

	var countAPIs int64
	s.db.Model(&dao.API{}).Where("service = ?", service).Count(&countAPIs)
	assert.Equal(s.T(), int64(1), countAPIs)

	var countBindings int64
	s.db.Model(&dao.PermissionBinding{}).Where("perm_code = ?", "test:perm:p1").Count(&countBindings)
	assert.Equal(s.T(), int64(1), countBindings)

	// 3. 构造第二次 Ingest Snap2 (资产发生了颠覆性修改，原来 p1, api1 被彻底拿掉，换成了 p2, api2)
	snap2 := ingestion.Snapshot{
		Service: service,
		Permissions: []domain.Permission{
			{Code: "test:perm:p2", Name: "权限2", Group: "组2", Service: service},
		},
		APIs: []domain.API{
			{Service: service, Method: "POST", Path: "/api/v1/p2", Name: "接口2"},
		},
		Bindings: map[string][]string{
			"test:perm:p2": {"post:/api/v1/p2"},
		},
	}

	err = engine.Ingest(ctx, snap2)
	require.NoError(s.T(), err)

	// 验证强一致对齐效果：
	// A. 旧权限和旧 API 已经被物理删除，新权限和新 API 成功录入
	s.db.Model(&dao.Permission{}).Where("service = ?", service).Count(&countPerms)
	assert.Equal(s.T(), int64(1), countPerms) // 总共依然是 1 个
	var p dao.Permission
	err = s.db.Where("service = ?", service).First(&p).Error
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "test:perm:p2", p.Code) // 应该是 p2

	s.db.Model(&dao.API{}).Where("service = ?", service).Count(&countAPIs)
	assert.Equal(s.T(), int64(1), countAPIs) // 总共依然是 1 个
	var a dao.API
	err = s.db.Where("service = ?", service).First(&a).Error
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "/api/v1/p2", a.Path) // 应该是 p2

	// B. 旧的绑定关系已经被完全删除，新的绑定关系成功录入
	s.db.Model(&dao.PermissionBinding{}).Where("perm_code = ?", "test:perm:p1").Count(&countBindings)
	assert.Equal(s.T(), int64(0), countBindings) // p1 绑定应该为 0

	s.db.Model(&dao.PermissionBinding{}).Where("perm_code = ?", "test:perm:p2").Count(&countBindings)
	assert.Equal(s.T(), int64(1), countBindings) // p2 绑定应该为 1
}

func (s *PermissionSuite) TestIngestMenusAndPhysicalClearProtection() {
	s.clearAll()

	permDAO := dao.NewPermissionDAO(s.db)
	resDAO := dao.NewResourceDAO(s.db)
	svcDAO := dao.NewServiceDAO(s.db)
	engine := ingestion.NewEngine(
		repository.NewPermissionRepository(permDAO),
		repository.NewResourceRepository(resDAO),
		repository.NewServiceRepository(svcDAO),
	)

	ctx := context.Background()

	// 1. 模拟全量对齐菜单绑定。此时数据库中并没有 "test:perm:p1" 的 Permission 记录
	menus := domain.MenuTree{
		{
			Name:           "TestMenu",
			Path:           "/test",
			PermissionCode: "test:perm:p1",
		},
	}
	err := engine.IngestMenus(ctx, menus)
	require.NoError(s.T(), err)

	// 验证菜单已同步，且其绑定的 perm_id 此时是 0
	var pb dao.PermissionBinding
	err = s.db.Where("resource_urn = ?", "eiam:menu:TestMenu").First(&pb).Error
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "test:perm:p1", pb.PermCode)
	assert.Equal(s.T(), int64(0), pb.PermId)

	// 2. 模拟服务 A 上报权限和 API
	service := "test_svc"
	snap := ingestion.Snapshot{
		Service: service,
		Permissions: []domain.Permission{
			{Code: "test:perm:p1", Name: "权限1", Group: "组1", Service: service},
		},
		APIs: []domain.API{
			{Service: service, Method: "GET", Path: "/api/v1/p1", Name: "接口1"},
		},
		Bindings: map[string][]string{
			"test:perm:p1": {"get:/api/v1/p1"},
		},
	}

	// 执行 Ingest。此时会经历 PhysicalClearService，它不能删掉刚才的 menu 绑定
	err = engine.Ingest(ctx, snap)
	require.NoError(s.T(), err)

	// 3. 验证效果
	// A. 菜单绑定还在，并没有被 PhysicalClearService 误删
	var pbAfter dao.PermissionBinding
	err = s.db.Where("resource_urn = ?", "eiam:menu:TestMenu").First(&pbAfter).Error
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "test:perm:p1", pbAfter.PermCode)

	// B. 对应的权限已被写入
	var perm dao.Permission
	err = s.db.Where("code = ?", "test:perm:p1").First(&perm).Error
	require.NoError(s.T(), err)

	// 4. 重启服务/重新 Ingest，验证依然稳定且不会丢失绑定
	err = engine.Ingest(ctx, snap)
	require.NoError(s.T(), err)

	// 再次验证菜单绑定依然正常存在
	var pbReload dao.PermissionBinding
	err = s.db.Where("resource_urn = ?", "eiam:menu:TestMenu").First(&pbReload).Error
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "test:perm:p1", pbReload.PermCode)
}

func TestPermissionSuite(t *testing.T) {
	suite.Run(t, new(PermissionSuite))
}
