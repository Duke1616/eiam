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
	permissionhdl "github.com/Duke1616/eiam/internal/web/permission"
	"github.com/Duke1616/eiam/internal/web/policy"
	resourcehdl "github.com/Duke1616/eiam/internal/web/resource"
	rolehdl "github.com/Duke1616/eiam/internal/web/role"
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

	// 其他全局配置注入
	InitServiceConfig,
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
		resource.NewResourceInitializer,
		permission.NewPermissionService,

		// Handlers
		user.NewUserHandler,
		policy.NewHandler,
		tenanthdl.NewHandler,
		resourcehdl.NewHandler,
		// Handlers (Capabilities)
		permissionhdl.NewPermissionHandler,
		rolehdl.NewHandler,

		// Providers Registry
		InitProviders,

		// App Component
		InitGinMiddlewares,
		InitGinWebServer,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
