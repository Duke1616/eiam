//go:build wireinject

package ioc

import (
	"github.com/Duke1616/eiam/internal/grpc"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/repository/dao"
	deptsvc "github.com/Duke1616/eiam/internal/service/department"
	"github.com/Duke1616/eiam/internal/service/discovery"
	groupsvc "github.com/Duke1616/eiam/internal/service/group"
	invitationsvc "github.com/Duke1616/eiam/internal/service/invitation"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/permission/checker"
	policysvc "github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/resource/ingestion"
	role "github.com/Duke1616/eiam/internal/service/role"
	tenantsvc "github.com/Duke1616/eiam/internal/service/tenant"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/internal/service/user/ldap"
	"github.com/Duke1616/eiam/internal/service/user/passkey"
	depthdl "github.com/Duke1616/eiam/internal/web/department"
	discoveryhdl "github.com/Duke1616/eiam/internal/web/discovery"
	grouphdl "github.com/Duke1616/eiam/internal/web/group"
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
	InitCapabilityRegistry,

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
		dao.NewTenantKeyDAO,
		dao.NewRoleDAO,
		dao.NewPermissionDAO,
		dao.NewResourceDAO,
		dao.NewServiceDAO,
		dao.NewPolicyDAO,
		dao.NewIdentitySourceDAO,
		dao.NewInvitationDAO,
		dao.NewDepartmentDAO,
		dao.NewGroupDAO,

		// Repositories
		repository.NewUserRepository,
		repository.NewTenantRepository,
		repository.NewTenantKeyRepository,
		repository.NewRoleRepository,
		repository.NewPermissionRepository,
		repository.NewResourceRepository,
		repository.NewServiceRepository,
		repository.NewPolicyRepository,
		repository.NewIdentitySourceRepository,
		repository.NewInvitationRepository,
		repository.NewDepartmentRepository,
		repository.NewGroupRepository,

		// Services
		usersvc.NewUserService,
		passkey.NewPasskeyService,
		ldap.NewLdapService,
		tenantsvc.NewTenantService,
		tenantsvc.NewTenantKeyService,
		role.NewRoleService,
		resource.NewResourceService,
		resource.NewResourceInitializer,
		ingestion.NewEngine,
		permission.NewPermissionService,
		discovery.NewWorker,
		checker.NewBoundaryChecker,
		policysvc.NewPolicyService,
		invitationsvc.NewInvitationService,
		InitIdentitySourceService,
		deptsvc.NewDepartmentService,
		groupsvc.NewGroupService,

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
		depthdl.NewHandler,
		grouphdl.NewHandler,

		// Providers Registry
		InitProviders,

		// Providers 检索注册
		InitSearchSubjectProviders,

		// App Component
		InitTasks,
		InitGinMiddlewares,
		middleware.NewTenancyBuilder,
		InitGinWebServer,

		// GRPC Server
		grpc.NewUserServer,
		grpc.NewTenantServiceServer,
		InitGrpcServer,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
