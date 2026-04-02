//go:build wireinject

package ioc

import (
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	tenantsvc "github.com/Duke1616/eiam/internal/service/tenant"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/internal/web/policy"
	tenanthdl "github.com/Duke1616/eiam/internal/web/tenant"
	"github.com/Duke1616/eiam/internal/web/user"
	"github.com/google/wire"
)

var BaseSet = wire.NewSet(
	InitDB,
	InitRedis,
	InitSession,
	InitCasbin,
	InitListener,
	InitOPA,

	// LDAP 基础设施
	InitLdapConfig,
	InitIdentityProviders,
)

func InitApp() (*App, error) {
	wire.Build(
		BaseSet,
		// DAOs
		dao.NewUserDAO,
		dao.NewTenantDAO,
		dao.NewRoleDAO,
		dao.NewPermissionDAO,
		dao.NewResourceDAO,

		// Repositories
		repository.NewUserRepository,
		repository.NewTenantRepository,
		repository.NewRoleRepository,
		repository.NewPermissionRepository,
		repository.NewResourceRepository,

		// Services
		usersvc.NewUserService,
		tenantsvc.NewTenantService,
		role.NewRoleService,
		resource.NewResourceService,
		permission.NewPermissionService,

		// Handlers
		user.NewUserHandler,
		policy.NewHandler,
		tenanthdl.NewHandler,

		// App Component
		InitGinMiddlewares,
		InitGinWebServer,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
