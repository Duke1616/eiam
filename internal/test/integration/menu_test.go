package integration

import (
	"context"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type MenuTreeSuite struct {
	PermissionSuite
}

func (s *MenuTreeSuite) TestGetAuthorizedMenus() {
	t := s.T()
	ctx := context.Background()
	tenantId := int64(999)
	ctxWithTenant := ctxutil.WithTenantID(ctx, tenantId)

	// 1. 同步复杂菜单树 (模拟从 YAML 导入的任务)
	// Parent: System (100) -> Child: User (101), Child: Role (102)
	testMenus := []*domain.Menu{
		{
			Name: "系统管理", Path: "/system",
			Children: []*domain.Menu{
				{Name: "用户管理", Path: "/system/user"},
				{Name: "角色管理", Path: "/system/role"},
			},
		},
	}
	err := s.resourceSvc.SyncMenus(ctxWithTenant, testMenus)
	require.NoError(t, err)

	// 2. 绑定权限码 (让所有菜单都受控，不再是“公共”的)
	pRoot, _ := s.permSvc.CreatePermission(ctxWithTenant, domain.Permission{Code: "sys:all", Name: "全系统"})
	pUser, _ := s.permSvc.CreatePermission(ctxWithTenant, domain.Permission{Code: "sys:user:view", Name: "用户查看"})
	pRole, _ := s.permSvc.CreatePermission(ctxWithTenant, domain.Permission{Code: "sys:role:view", Name: "角色查看"})

	_ = s.permSvc.BindResourcesToPermission(ctxWithTenant, pRoot, "sys:all", []string{testMenus[0].URN()})
	_ = s.permSvc.BindResourcesToPermission(ctxWithTenant, pUser, "sys:user:view", []string{testMenus[0].Children[0].URN()})
	_ = s.permSvc.BindResourcesToPermission(ctxWithTenant, pRole, "sys:role:view", []string{testMenus[0].Children[1].URN()})

	// 3. 授权给用户 (只有系统查看权和用户查看权，没有角色查看权)
	var userId int64 = 8888
	_, _ = s.roleSvc.Create(ctxWithTenant, domain.Role{Code: "USER_ADMIN", TenantID: tenantId})
	_ = s.roleSvc.UpdatePolicies(ctxWithTenant, "USER_ADMIN", []domain.Policy{
		{Statement: []domain.Statement{
			{Effect: domain.Allow, Resource: []string{"*"}, Action: []string{"sys:all"}},
			{Effect: domain.Allow, Resource: []string{"*"}, Action: []string{"sys:user:view"}},
		}},
	})
	_, _ = s.permSvc.AssignRoleToUser(ctxWithTenant, userId, "USER_ADMIN")

	// 4. 执行获取
	menus, err := s.permSvc.GetAuthorizedMenus(ctxWithTenant, userId)
	require.NoError(t, err)

	// 5. 断言
	// 预期：系统管理(Parent) 存在，且其子项只有 用户管理(m2)，角色管理(m3) 被过滤掉
	assert.Len(t, menus, 1)
	assert.Equal(t, "系统管理", menus[0].Name)
	assert.Len(t, menus[0].Children, 1)
	assert.Equal(t, "用户管理", menus[0].Children[0].Name)
}

func TestMenuTreeSuite(t *testing.T) {
	suite.Run(t, new(MenuTreeSuite))
}
