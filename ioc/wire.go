//go:build wireinject

package ioc

import (
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/internal/service/discovery"
	invitationsvc "github.com/Duke1616/eiam/internal/service/invitation"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/permission/checker"
	policysvc "github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/internal/service/resource"
	role "github.com/Duke1616/eiam/internal/service/role"
	tenantsvc "github.com/Duke1616/eiam/internal/service/tenant"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/internal/service/user/ldap"
	"github.com/Duke1616/eiam/internal/service/user/passkey"
	discoveryhdl "github.com/Duke1616/eiam/internal/web/discovery"
	idhdl "github.com/Duke1616/eiam/internal/web/identity_source"
	invitationhdl "github.com/Duke1616/eiam/internal/web/invitation"
	permissionhdl "github.com/Duke1616/eiam/internal/web/permission"
	"github.com/Duke1616/eiam/internal/web/policy"
	rolehdl "github.com/Duke1616/eiam/internal/web/role"
	tenanthdl "github.com/Duke1616/eiam/internal/web/tenant"
	userhdl "github.com/Duke1616/eiam/internal/web/user"
	"github.com/Duke1616/eiam/pkg/web/middleware"
	"github.com/RediSearch/redisearch-go/v2/redisearch"
	"github.com/google/wire"
)

var webSet = wire.NewSet(
	userhdl.NewUserHandler,
	policy.NewHandler,
	tenanthdl.NewHandler,
	permissionhdl.NewHandler,
	rolehdl.NewHandler,
	idhdl.NewHandler,
	invitationhdl.NewHandler,
	discoveryhdl.NewHandler,
)

var BaseSet = wire.NewSet(
	InitDB,
	InitRedis,
	InitSession,
	InitCasbin,
	InitListener,
	InitOPA,
	InitEtcd,
	InitDLock,
	InitRegistry,

	// LDAP 基础设施
	InitRedisSearch,
	InitCredentialProviders,

	// 其他全局配置注入
	InitServiceConfig,
	InitCryptoManager,
)

func InitLdapUserCache(conn *redisearch.Client) cache.RedisearchLdapUserCache {
	return cache.NewRedisearchLdapUserCache(conn)
}

func InitApp() (*App, error) {
	wire.Build(
		BaseSet,

		// Cache
		InitLdapUserCache,
		cache.NewIdentitySourceCache,
		cache.NewUserCache,

		// DAOs
		dao.NewUserDAO,
		dao.NewTenantDAO,
		dao.NewRoleDAO,
		dao.NewPermissionDAO,
		dao.NewResourceDAO,
		dao.NewServiceDAO,
		dao.NewPolicyDAO,
		dao.NewIdentitySourceDAO,
		dao.NewInvitationDAO,

		// Repositories
		repository.NewUserRepository,
		repository.NewTenantRepository,
		repository.NewRoleRepository,
		repository.NewPermissionRepository,
		repository.NewResourceRepository,
		repository.NewServiceRepository,
		repository.NewPolicyRepository,
		repository.NewIdentitySourceRepository,
		repository.NewInvitationRepository,

		// Services
		usersvc.NewUserService,
		passkey.NewPasskeyService,
		ldap.NewLdapService,
		tenantsvc.NewTenantService,
		role.NewRoleService,
		resource.NewResourceService,
		resource.NewResourceInitializer,
		resource.NewReconciler,
		permission.NewPermissionService,
		discovery.NewWorker,
		checker.NewBoundaryChecker,
		policysvc.NewPolicyService,
		invitationsvc.NewInvitationService,
		InitIdentitySourceService,

		// Handlers
		userhdl.NewUserHandler,
		policy.NewHandler,
		tenanthdl.NewHandler,
		idhdl.NewHandler,
		invitationhdl.NewHandler,
		discoveryhdl.NewHandler,
		// Handlers (Capabilities)
		permissionhdl.NewHandler,
		rolehdl.NewHandler,

		// Providers Registry
		InitProviders,

		// Providers 检索注册
		InitSearchSubjectProviders,

		// App Component
		InitTasks,
		InitGinMiddlewares,
		middleware.NewTenancyBuilder,
		InitGinWebServer,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
