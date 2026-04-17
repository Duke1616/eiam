//go:build wireinject

package ioc

import (
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/internal/service/permission"
	policysvc "github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/internal/service/resource"
	role "github.com/Duke1616/eiam/internal/service/role"
	tenantsvc "github.com/Duke1616/eiam/internal/service/tenant"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	permissionhdl "github.com/Duke1616/eiam/internal/web/permission"
	"github.com/Duke1616/eiam/internal/web/policy"
	resourcehdl "github.com/Duke1616/eiam/internal/web/resource"
	rolehdl "github.com/Duke1616/eiam/internal/web/role"
	tenanthdl "github.com/Duke1616/eiam/internal/web/tenant"
	"github.com/Duke1616/eiam/internal/web/user"
	"github.com/RediSearch/redisearch-go/v2/redisearch"
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
	InitRedisSearch,
	InitLdapConfig,
	InitIdentityProviders,

	// 其他全局配置注入
	InitServiceConfig,
)

func InitLdapUserCache(conn *redisearch.Client) cache.RedisearchLdapUserCache {
	return cache.NewRedisearchLdapUserCache(conn)
}

func InitApp() (*App, error) {
	wire.Build(
		BaseSet,

		// Cache
		InitLdapUserCache,

		// DAOs
		dao.NewUserDAO,
		dao.NewTenantDAO,
		dao.NewRoleDAO,
		dao.NewPermissionDAO,
		dao.NewResourceDAO,
		dao.NewServiceDAO,
		dao.NewPolicyDAO,

		// Repositories
		repository.NewUserRepository,
		repository.NewTenantRepository,
		repository.NewRoleRepository,
		repository.NewPermissionRepository,
		repository.NewResourceRepository,
		repository.NewServiceRepository,
		repository.NewPolicyRepository,

		// Services
		usersvc.NewUserService,
		usersvc.NewLdapService,
		tenantsvc.NewTenantService,
		role.NewRoleService,
		resource.NewResourceService,
		resource.NewResourceInitializer,
		permission.NewPermissionService,
		policysvc.NewPolicyService,

		// Handlers
		user.NewUserHandler,
		policy.NewHandler,
		tenanthdl.NewHandler,
		resourcehdl.NewHandler,
		// Handlers (Capabilities)
		permissionhdl.NewHandler,
		rolehdl.NewHandler,

		// Providers Registry
		InitProviders,

		// Providers 检索注册
		InitSearchSubjectProviders,

		// App Component
		InitGinMiddlewares,
		InitGinWebServer,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
