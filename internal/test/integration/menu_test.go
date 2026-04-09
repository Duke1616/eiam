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
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"
)

type MenuTreeSuite struct {
	suite.Suite

	db       *gorm.DB
	enforcer *casbin.SyncedEnforcer
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

func (s *MenuTreeSuite) SetupSuite() {
	// 1. 初始化运行配置项
	dir, err := os.Getwd()
	require.NoError(s.T(), err)
	viper.SetConfigFile(filepath.Join(dir, "../config/config.yaml"))
	err = viper.ReadInConfig()
	require.NoError(s.T(), err, "请确保能在当前目录的上两级找到 config/config.yaml")

	// 2. 初始化集成测试依赖
	deps, err := testioc.InitPermissionSuiteDeps()
	require.NoError(s.T(), err)

	s.db = deps.DB
	s.enforcer = deps.Enforcer
	s.permSvc = deps.PermSvc
	s.tenantSvc = deps.TenantSvc
	s.resourceSvc = deps.ResourceSvc
	s.roleSvc = deps.RoleSvc

	s.testUid = 8888
}

func (s *MenuTreeSuite) TearDownSubTest() {
	s.clearAll()
}

func (s *MenuTreeSuite) SetupSubTest() {
	s.clearAll() // 前置清理，防止场景干扰

	// 初始化租户 (每个场景共用一个干净的租户环境)
	tid, err := s.tenantSvc.CreateTenant(context.Background(), "测试中心", "test-center", 12345)
	require.NoError(s.T(), err)
	s.testTid = tid
}

func (s *MenuTreeSuite) TestGetAuthorizedMenus() {
	testCases := []struct {
		name   string
		before func(t *testing.T)
		verify func(t *testing.T, menus []domain.Menu)
	}{
		{
			name: "场景1: 用户拥有全量菜单权限 -> 预期可见完整树",
			before: func(t *testing.T) {
				ctx := ctxutil.WithTenantID(context.Background(), s.testTid)

				// 1. 同步菜单
				testMenus := []*domain.Menu{
					{
						Name: "系统管理", Path: "/system",
						Children: []*domain.Menu{
							{Name: "用户管理", Path: "/system/user"},
							{Name: "角色管理", Path: "/system/role"},
						},
					},
				}
				err := s.resourceSvc.SyncMenus(ctx, testMenus)
				require.NoError(t, err)

				// 2. 创建并授权角色
				_, err = s.roleSvc.Create(ctx, domain.Role{
					Code: "ALL_VIEWER",
					Policies: []domain.Policy{
						{Statement: []domain.Statement{
							{Effect: domain.Allow, Resource: []string{"*"}, Action: []string{"*"}},
						}},
					},
				})
				require.NoError(t, err)
				_, err = s.permSvc.AssignRoleToUser(ctx, s.testUid, "ALL_VIEWER")
				require.NoError(t, err)
			},
			verify: func(t *testing.T, menus []domain.Menu) {
				assert.Len(t, menus, 1)
				assert.Equal(t, "系统管理", menus[0].Name)
				assert.Len(t, menus[0].Children, 2)
			},
		},
		{
			name: "场景2: 用户仅拥有部分子菜单权限 -> 预期父菜单保留，子菜单按需过滤",
			before: func(t *testing.T) {
				ctx := ctxutil.WithTenantID(context.Background(), s.testTid)

				// 1. 同步菜单
				testMenus := []*domain.Menu{
					{
						Name: "资产中心", Path: "/asset",
						Children: []*domain.Menu{
							{Name: "服务器", Path: "/asset/server"},
							{Name: "数据库", Path: "/asset/db"},
						},
					},
				}
				err := s.resourceSvc.SyncMenus(ctx, testMenus)
				require.NoError(t, err)

				// 2. 绑定权限 (重要：让菜单全部受控)
				p1, err := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "p1", Name: "权限1"})
				require.NoError(t, err)
				p2, err := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "p2", Name: "权限2"})
				require.NoError(t, err)

				err = s.permSvc.BindResourcesToPermission(ctx, p1, "p1", []string{testMenus[0].Children[0].URN()})
				require.NoError(t, err)
				err = s.permSvc.BindResourcesToPermission(ctx, p2, "p2", []string{testMenus[0].Children[1].URN()})
				require.NoError(t, err)

				// 3. 授权 (只允许访问服务器 p1，且不授权数据库 p2)
				_, err = s.roleSvc.Create(ctx, domain.Role{
					Code: "SERVER_VIEWER",
					Policies: []domain.Policy{
						{Statement: []domain.Statement{
							{Effect: domain.Allow, Resource: []string{"*"}, Action: []string{"p1"}},
						}},
					},
				})
				require.NoError(t, err)
				_, err = s.permSvc.AssignRoleToUser(ctx, s.testUid, "SERVER_VIEWER")
				require.NoError(t, err)
			},
			verify: func(t *testing.T, menus []domain.Menu) {
				assert.Len(t, menus, 1)
				assert.Equal(t, "资产中心", menus[0].Name)
				assert.Len(t, menus[0].Children, 1)
				assert.Equal(t, "服务器", menus[0].Children[0].Name)
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			tc.before(s.T())

			ctx := ctxutil.WithTenantID(context.Background(), s.testTid)
			menus, err := s.permSvc.GetAuthorizedMenus(ctx, s.testUid)
			require.NoError(s.T(), err)

			tc.verify(s.T(), menus)
		})
	}
}

func (s *MenuTreeSuite) clearAll() {
	s.db.Exec("DROP TABLE IF EXISTS goose_db_version")
	s.db.Exec("DELETE FROM casbin_rule")
	s.db.Exec("DELETE FROM permission")
	s.db.Exec("DELETE FROM permission_binding")
	s.db.Exec("DELETE FROM role")
	s.db.Exec("DELETE FROM tenant")
	s.db.Exec("DELETE FROM membership")
	s.db.Exec("DELETE FROM menu")
}

func TestMenuTreeSuite(t *testing.T) {
	suite.Run(t, new(MenuTreeSuite))
}
