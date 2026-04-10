package integration

import (
	"context"
	"fmt"
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
	testUid int64
}

func (s *MenuTreeSuite) SetupSuite() {
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

	s.testUid = 12345
}

func (s *MenuTreeSuite) TearDownSubTest() {
	s.clearAll()
}

func (s *MenuTreeSuite) TearDownTest() {
	s.clearAll()
}

func (s *MenuTreeSuite) ensureAdminRole(ctx context.Context) {
	_, _ = s.roleSvc.Create(ctx, domain.Role{Code: "ADMIN", Name: "系统管理员"})
}

func (s *MenuTreeSuite) TestGetAuthorizedMenus() {
	testCases := []struct {
		name   string
		before func(ctx context.Context)
		verify func(t *testing.T, menus domain.MenuTree)
	}{
		{
			name: "场景1: 用户拥有全量菜单权限 -> 预期可见完整树",
			before: func(ctx context.Context) {
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
				require.NoError(s.T(), err)

				_, err = s.roleSvc.Create(ctx, domain.Role{
					Code: "ALL_VIEWER",
					Policies: []domain.Policy{
						{Statement: []domain.Statement{
							{Effect: domain.Allow, Resource: []string{"*"}, Action: []string{"*"}},
						}},
					},
				})
				require.NoError(s.T(), err)
				_, err = s.permSvc.AssignRoleToUser(ctx, s.testUid, "ALL_VIEWER")
				require.NoError(s.T(), err)
			},
			verify: func(t *testing.T, menus domain.MenuTree) {
				require.Len(t, menus, 1)
				assert.Equal(t, "系统管理", menus[0].Name)
				assert.Len(t, menus[0].Children, 2)
			},
		},
		{
			name: "场景2: 用户仅拥有部分子菜单权限 -> 预期父菜单保留，子菜单按需过滤",
			before: func(ctx context.Context) {
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
				require.NoError(s.T(), err)

				p1, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "p1", Name: "权限1"})
				_ = s.permSvc.BindResourcesToPermission(ctx, p1, "p1", []string{"eiam:iam:menu:/asset/server"})

				p2, _ := s.permSvc.CreatePermission(ctx, domain.Permission{Code: "p2", Name: "权限2"})
				_ = s.permSvc.BindResourcesToPermission(ctx, p2, "p2", []string{"eiam:iam:menu:/asset/db"})

				_, err = s.roleSvc.Create(ctx, domain.Role{
					Code: "SERVER_VIEWER",
					Policies: []domain.Policy{
						{Statement: []domain.Statement{
							{Effect: domain.Allow, Resource: []string{"*"}, Action: []string{"p1"}},
						}},
					},
				})
				require.NoError(s.T(), err)
				_, err = s.permSvc.AssignRoleToUser(ctx, s.testUid, "SERVER_VIEWER")
				require.NoError(s.T(), err)
			},
			verify: func(t *testing.T, menus domain.MenuTree) {
				require.Len(t, menus, 1)
				assert.Equal(t, "资产中心", menus[0].Name)
				assert.Len(t, menus[0].Children, 1)
				assert.Equal(t, "服务器", menus[0].Children[0].Name)
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			defer s.clearAll()

			s.ensureAdminRole(context.Background())

			tid, err := s.tenantSvc.CreateTenant(context.Background(), "测试中心", "test-center", s.testUid)
			require.NoError(s.T(), err)
			ctx := ctxutil.WithTenantID(context.Background(), tid)
			ctx = ctxutil.WithUserID(ctx, s.testUid)

			tc.before(ctx)
			menus, err := s.permSvc.GetAuthorizedMenus(ctx, s.testUid)
			require.NoError(s.T(), err)

			tc.verify(s.T(), menus)
		})
	}
}

func (s *MenuTreeSuite) clearAll() {
	// 使用带 AllowGlobalUpdate 的 Session，并显式绕过所有条件
	db := s.db.Session(&gorm.Session{AllowGlobalUpdate: true})
	tables := []string{"menu", "role", "permission", "permission_binding", "casbin_rule", "tenant", "membership"}
	for _, table := range tables {
		_ = db.Exec(fmt.Sprintf("DELETE FROM `%s` WHERE 1=1", table))
	}

	_ = s.enforcer.LoadPolicy()
}

func TestMenuTreeSuite(t *testing.T) {
	suite.Run(t, new(MenuTreeSuite))
}
