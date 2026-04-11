//go:build wireinject

package testioc

import (
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/internal/service/permission"
	policysvc "github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/internal/service/tenant"
	mainioc "github.com/Duke1616/eiam/ioc"
	"github.com/google/wire"
)

func InitPermissionSuiteDeps() (*PermissionSuiteDeps, error) {
	wire.Build(
		// 基础组件：使用 testioc 本地定义的 InitDB (跳过 goose 迁移)
		InitDB,
		mainioc.InitCasbin,
		mainioc.InitOPA,

		// DAOs
		dao.NewTenantDAO,
		dao.NewRoleDAO,
		dao.NewResourceDAO,
		dao.NewPermissionDAO,
		dao.NewPolicyDAO,
		dao.NewServiceDAO,

		// Repositories
		repository.NewTenantRepository,
		repository.NewRoleRepository,
		repository.NewResourceRepository,
		repository.NewPermissionRepository,
		repository.NewPolicyRepository,
		repository.NewServiceRepository,

		// Services
		role.NewRoleService,
		resource.NewResourceService,
		permission.NewPermissionService,
		policysvc.NewPolicyService,
		tenant.NewTenantService,

		// 组装返回结构
		wire.Struct(new(PermissionSuiteDeps), "*"),
	)
	return new(PermissionSuiteDeps), nil
}
