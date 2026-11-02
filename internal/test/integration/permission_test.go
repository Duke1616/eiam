package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	cachemocks "github.com/Duke1616/eiam/internal/repository/cache/mocks"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/internal/service/permission"
	policysvc "github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/resource/ingestion"
	rolesvc "github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/internal/service/tenant"
	testioc "github.com/Duke1616/eiam/internal/test/ioc"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/gormx"
	"github.com/casbin/casbin/v2"
	"github.com/redis/go-redis/v9"
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
	redis    redis.Cmdable
	enforcer *casbin.SyncedEnforcer
	ctrl     *gomock.Controller

	permSvc     permission.IPermissionService
	tenantSvc   tenant.ITenantService
	roleSvc     rolesvc.IRoleService
	policySvc   policysvc.IPolicyService
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
	s.redis = deps.Redis
	s.enforcer = deps.Enforcer
	s.permSvc = deps.PermSvc
	s.tenantSvc = deps.TenantSvc
	s.roleSvc = deps.RoleSvc
	s.policySvc = deps.PolicySvc
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
	if s.redis != nil {
		s.redis.FlushDB(context.Background())
	}
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
	permCache := cachemocks.NewMockIPermissionCache(s.ctrl)
	permCache.EXPECT().DeleteCodesByResources(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	permCache.EXPECT().ClearAllPermissionCaches(gomock.Any()).Return(nil).AnyTimes()
	resCache := cachemocks.NewMockIResourceCache(s.ctrl)
	resCache.EXPECT().InvalidateServiceAPIs(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	engine := ingestion.NewEngine(
		repository.NewPermissionRepository(permDAO, permCache),
		repository.NewResourceRepository(resDAO, resCache),
		repository.NewServiceRepository(svcDAO),
	)

	ctx := gormx.IgnoreTenantContext(context.Background())
	db := s.db.WithContext(ctx)
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
	db.Model(&dao.Permission{}).Where("service = ?", service).Count(&countPerms)
	assert.Equal(s.T(), int64(1), countPerms)

	var countAPIs int64
	db.Model(&dao.API{}).Where("service = ?", service).Count(&countAPIs)
	assert.Equal(s.T(), int64(1), countAPIs)

	var countBindings int64
	db.Model(&dao.PermissionBinding{}).Where("perm_code = ?", "test:perm:p1").Count(&countBindings)
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
	db.Model(&dao.Permission{}).Where("service = ?", service).Count(&countPerms)
	assert.Equal(s.T(), int64(1), countPerms) // 总共依然是 1 个
	var p dao.Permission
	err = db.Where("service = ?", service).First(&p).Error
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "test:perm:p2", p.Code) // 应该是 p2

	db.Model(&dao.API{}).Where("service = ?", service).Count(&countAPIs)
	assert.Equal(s.T(), int64(1), countAPIs) // 总共依然是 1 个
	var a dao.API
	err = db.Where("service = ?", service).First(&a).Error
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "/api/v1/p2", a.Path) // 应该是 p2

	// B. 旧的绑定关系已经被完全删除，新的绑定关系成功录入
	db.Model(&dao.PermissionBinding{}).Where("perm_code = ?", "test:perm:p1").Count(&countBindings)
	assert.Equal(s.T(), int64(0), countBindings) // p1 绑定应该为 0

	db.Model(&dao.PermissionBinding{}).Where("perm_code = ?", "test:perm:p2").Count(&countBindings)
	assert.Equal(s.T(), int64(1), countBindings) // p2 绑定应该为 1
}

func (s *PermissionSuite) TestIngestMenusAndPhysicalClearProtection() {
	s.clearAll()

	permDAO := dao.NewPermissionDAO(s.db)
	resDAO := dao.NewResourceDAO(s.db)
	svcDAO := dao.NewServiceDAO(s.db)
	permCache := cachemocks.NewMockIPermissionCache(s.ctrl)
	permCache.EXPECT().DeleteCodesByResources(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	permCache.EXPECT().ClearAllPermissionCaches(gomock.Any()).Return(nil).AnyTimes()
	resCache := cachemocks.NewMockIResourceCache(s.ctrl)
	resCache.EXPECT().InvalidateServiceAPIs(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	engine := ingestion.NewEngine(
		repository.NewPermissionRepository(permDAO, permCache),
		repository.NewResourceRepository(resDAO, resCache),
		repository.NewServiceRepository(svcDAO),
	)

	ctx := gormx.IgnoreTenantContext(context.Background())
	db := s.db.WithContext(ctx)

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
	err = db.Where("resource_urn = ?", "eiam:menu:TestMenu").First(&pb).Error
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
	err = db.Where("resource_urn = ?", "eiam:menu:TestMenu").First(&pbAfter).Error
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "test:perm:p1", pbAfter.PermCode)

	// B. 对应的权限已被写入
	var perm dao.Permission
	err = db.Where("code = ?", "test:perm:p1").First(&perm).Error
	require.NoError(s.T(), err)

	// 4. 重启服务/重新 Ingest，验证依然稳定且不会丢失绑定
	err = engine.Ingest(ctx, snap)
	require.NoError(s.T(), err)

	// 再次验证菜单绑定依然正常存在
	var pbReload dao.PermissionBinding
	err = db.Where("resource_urn = ?", "eiam:menu:TestMenu").First(&pbReload).Error
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "test:perm:p1", pbReload.PermCode)
}

// setupAPIWithPermission 快速创建测试 API 与关联的权限点
func (s *PermissionSuite) setupAPIWithPermission(ctx context.Context, service, method, path, permCode string) {
	api := domain.API{Service: service, Method: method, Path: path}
	_, err := s.resourceSvc.CreateAPI(ctx, api)
	s.Require().NoError(err)

	pid, err := s.permSvc.CreatePermission(ctx, domain.Permission{Code: permCode})
	s.Require().NoError(err)

	err = s.permSvc.BindResourcesToPermission(ctx, pid, permCode, []string{api.URN()})
	s.Require().NoError(err)
}

// setupRoleWithInlineAction 快速创建带有指定 Action 允许权限的角色并返回角色 ID
func (s *PermissionSuite) setupRoleWithInlineAction(ctx context.Context, roleCode, roleName, action string) int64 {
	id, err := s.roleSvc.Create(ctx, domain.Role{
		Code: roleCode,
		Name: roleName,
		InlinePolicies: []domain.Policy{
			{
				Statement: []domain.Statement{
					{Effect: domain.Allow, Action: []string{action}, Resource: []string{"*"}},
				},
			},
		},
	})
	s.Require().NoError(err)
	return id
}

func (s *PermissionSuite) TestCheckAPI_CacheLifecycle() {
	serviceName := "order-service"

	testCases := []struct {
		name   string
		before func(ctx context.Context, tid int64) (cacheKey, username, method, path string)
		run    func(ctx context.Context, tid int64)
		after  func(ctx context.Context, tid int64, cacheKey, username, method, path string)
	}{
		{
			name: "类型1-角色内联策略更新即时淘汰",
			before: func(ctx context.Context, tid int64) (string, string, string, string) {
				s.setupAPIWithPermission(ctx, serviceName, "GET", "/api/v1/orders", "order:view")
				s.setupRoleWithInlineAction(ctx, "ORDER_OPERATOR", "订单操作员", "order:view")
				_, err := s.permSvc.AssignRoleToUser(ctx, "alice", "ORDER_OPERATOR")
				s.Require().NoError(err)

				cacheKey := fmt.Sprintf("eiam:role:detail:%d:ORDER_OPERATOR", tid)
				// AssignRole 阶段系统已预热缓存，显式 Del 确保严格验证 CheckAPI 触发的冷启动与回填
				_ = s.redis.Del(ctx, cacheKey).Err()
				return cacheKey, "alice", "GET", "/api/v1/orders"
			},
			run: func(ctx context.Context, tid int64) {
				// 变更动作：收回内联权限，修改为 Deny All
				err := s.roleSvc.UpdateInlinePolicies(ctx, "ORDER_OPERATOR", []domain.Policy{
					{
						Statement: []domain.Statement{
							{Effect: domain.Deny, Action: []string{"*"}, Resource: []string{"*"}},
						},
					},
				})
				s.Require().NoError(err)
			},
		},
		{
			name: "类型2-主体托管策略解绑即时淘汰",
			before: func(ctx context.Context, tid int64) (string, string, string, string) {
				s.setupAPIWithPermission(ctx, serviceName, "POST", "/api/v1/orders", "order:create")
				_, err := s.policySvc.CreatePolicy(ctx, domain.Policy{
					Code: "ORDER_CREATOR_POLICY",
					Name: "订单创建权限",
					Statement: []domain.Statement{
						{Effect: domain.Allow, Action: []string{"order:create"}, Resource: []string{"*"}},
					},
				})
				s.Require().NoError(err)

				err = s.policySvc.AttachPolicyToUser(ctx, "bob", "ORDER_CREATOR_POLICY")
				s.Require().NoError(err)

				cacheKey := fmt.Sprintf("eiam:policy:attached_codes:%d:%s:bob", tid, domain.SubjectTypeUser)
				_ = s.redis.Del(ctx, cacheKey).Err()
				return cacheKey, "bob", "POST", "/api/v1/orders"
			},
			run: func(ctx context.Context, tid int64) {
				// 变更动作：解绑托管策略
				err := s.policySvc.DetachFromUser(ctx, "bob", "ORDER_CREATOR_POLICY")
				s.Require().NoError(err)
			},
		},
		{
			name: "类型3-托管策略规则定义修改即时淘汰详情缓存",
			before: func(ctx context.Context, tid int64) (string, string, string, string) {
				s.setupAPIWithPermission(ctx, serviceName, "PUT", "/api/v1/orders", "order:update")
				_, err := s.policySvc.CreatePolicy(ctx, domain.Policy{
					Code: "ORDER_EDITOR_POLICY",
					Name: "订单修改权限",
					Statement: []domain.Statement{
						{Effect: domain.Allow, Action: []string{"order:update"}, Resource: []string{"*"}},
					},
				})
				s.Require().NoError(err)

				err = s.policySvc.AttachPolicyToUser(ctx, "carol", "ORDER_EDITOR_POLICY")
				s.Require().NoError(err)

				// 针对策略详情缓存的淘汰验证
				cacheKey := fmt.Sprintf("eiam:policy:detail:%d:ORDER_EDITOR_POLICY", tid)
				return cacheKey, "carol", "PUT", "/api/v1/orders"
			},
			run: func(ctx context.Context, tid int64) {
				// 变更动作：更新策略本身的内容为 Deny
				targetPolicy, err := s.policySvc.GetPolicy(ctx, "ORDER_EDITOR_POLICY")
				s.Require().NoError(err)
				targetPolicy.Statement = []domain.Statement{
					{Effect: domain.Deny, Action: []string{"*"}, Resource: []string{"*"}},
				}
				err = s.policySvc.UpdatePolicy(ctx, targetPolicy)
				s.Require().NoError(err)
			},
		},
		{
			name: "类型4-角色解绑与删除即时驱逐缓存",
			before: func(ctx context.Context, tid int64) (string, string, string, string) {
				s.setupAPIWithPermission(ctx, serviceName, "DELETE", "/api/v1/orders", "order:delete")
				roleID := s.setupRoleWithInlineAction(ctx, "TEMP_ADMIN", "临时管理员", "order:delete")
				_, err := s.permSvc.AssignRoleToUser(ctx, "dave", "TEMP_ADMIN")
				s.Require().NoError(err)

				_ = roleID
				cacheKey := fmt.Sprintf("eiam:role:detail:%d:TEMP_ADMIN", tid)
				return cacheKey, "dave", "DELETE", "/api/v1/orders"
			},
			run: func(ctx context.Context, tid int64) {
				// 变更动作：先解除用户关联，再物理删除该角色
				_, err := s.permSvc.RemoveRoleFromUser(ctx, "dave", "TEMP_ADMIN")
				s.Require().NoError(err)

				targetRole, err := s.roleSvc.GetByCode(ctx, "TEMP_ADMIN")
				s.Require().NoError(err)

				err = s.roleSvc.Delete(ctx, targetRole.ID)
				s.Require().NoError(err)
			},
		},
	}

	for i, tc := range testCases {
		s.Run(tc.name, func() {
			defer s.clearAll()
			s.ensureAdminRole(context.Background())

			tid, err := s.tenantSvc.CreateTenant(context.Background(), tc.name, fmt.Sprintf("corp_%d", i), "super_user", int64(8000+i))
			s.Require().NoError(err)
			ctx := ctxutil.WithTenantID(context.Background(), tid)

			// 1. Before: 初始化环境、资产与主体授权
			cacheKey, username, method, path := tc.before(ctx, tid)

			// 2. 首次鉴权请求 (冷启动)，验证鉴权通过并自动回填 Redis
			ok, err := s.permSvc.CheckAPI(ctx, username, serviceName, method, path)
			s.Require().NoError(err)
			assert.True(s.T(), ok, "初始授权鉴权应当通过")

			// 验证 Redis 中对应缓存成功建立
			exists, err := s.redis.Exists(ctx, cacheKey).Result()
			s.Require().NoError(err)
			assert.Equal(s.T(), int64(1), exists, "首次鉴权后 Redis 缓存必须被成功写入")

			// 验证二次鉴权直接走缓存放行
			ok, err = s.permSvc.CheckAPI(ctx, username, serviceName, method, path)
			s.Require().NoError(err)
			assert.True(s.T(), ok, "命中缓存后的鉴权依然应通过")

			// 3. Run: 触发权限收回或实体变更
			tc.run(ctx, tid)

			// 4. After: 验证缓存强一致淘汰与鉴权即时生效
			if tc.after != nil {
				tc.after(ctx, tid, cacheKey, username, method, path)
			} else {
				// 统一标准断言：Redis 缓存必须已被物理驱逐，再次鉴权必须立刻被阻断 (无幽灵权限)
				exists, err = s.redis.Exists(ctx, cacheKey).Result()
				s.Require().NoError(err)
				assert.Equal(s.T(), int64(0), exists, "权限变更后 Redis 缓存必须被精准淘汰")

				ok, err = s.permSvc.CheckAPI(ctx, username, serviceName, method, path)
				s.Require().NoError(err)
				assert.False(s.T(), ok, "权限收回后再次鉴权必须立刻被拦截，绝无旧权限残留")
			}
		})
	}
}

func TestPermissionSuite(t *testing.T) {
	suite.Run(t, new(PermissionSuite))
}
