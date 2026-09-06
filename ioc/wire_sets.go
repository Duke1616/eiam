package ioc

import (
	auditevt "github.com/Duke1616/eiam/internal/event/audit"
	"github.com/Duke1616/eiam/internal/grpc"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/repository/dao"
	auditsvc "github.com/Duke1616/eiam/internal/service/audit"
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
	audithdl "github.com/Duke1616/eiam/internal/web/audit"
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
	idpsvc "github.com/Duke1616/eiam/internal/service/idp"
	idphdl "github.com/Duke1616/eiam/internal/web/idp"
	"github.com/Duke1616/eiam/pkg/web/middleware"
	"github.com/RediSearch/redisearch-go/v2/redisearch"
	"github.com/google/wire"
)

// InitLdapUserCache 构造 LDAP 用户检索专用缓存适配器
func InitLdapUserCache(conn *redisearch.Client) cache.RedisearchLdapUserCache {
	return cache.NewRedisearchLdapUserCache(conn)
}

var (
	// BaseSet 基础设施与全局配置 Provider 集合
	BaseSet = wire.NewSet(
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
		InitAuditConfig,
		InitAuditMatcher,
	)

	// UserSet 用户管理、身份源与多因素认证模块 Provider 集合
	UserSet = wire.NewSet(
		InitLdapUserCache,
		cache.NewUserCache,
		cache.NewIdentitySourceCache,
		dao.NewUserDAO,
		dao.NewIdentitySourceDAO,
		repository.NewUserRepository,
		repository.NewIdentitySourceRepository,
		usersvc.NewAuthCoordinator,
		usersvc.NewUserService,
		passkey.NewPasskeyService,
		ldap.NewLdapService,
		InitIdentitySourceService,
		userhdl.NewUserHandler,
		idhdl.NewHandler,
	)

	// TenantSet 多租户空间与租户 API 密钥模块 Provider 集合
	TenantSet = wire.NewSet(
		dao.NewTenantDAO,
		dao.NewTenantKeyDAO,
		repository.NewTenantRepository,
		repository.NewTenantKeyRepository,
		tenantsvc.NewTenantService,
		tenantsvc.NewTenantKeyService,
		tenanthdl.NewHandler,
	)

	// RoleSet 角色治理与继承图谱模块 Provider 集合
	RoleSet = wire.NewSet(
		dao.NewRoleDAO,
		repository.NewRoleRepository,
		role.NewRoleService,
		rolehdl.NewHandler,
	)

	// PermissionSet 权限管理、边界校验与 PBAC 策略模块 Provider 集合
	PermissionSet = wire.NewSet(
		cache.NewPermissionCache,
		dao.NewPermissionDAO,
		dao.NewPolicyDAO,
		repository.NewPermissionRepository,
		repository.NewPolicyRepository,
		permission.NewPermissionService,
		checker.NewBoundaryChecker,
		policysvc.NewPolicyService,
		permissionhdl.NewHandler,
		policy.NewHandler,
	)

	// DepartmentSet 部门组织架构模块 Provider 集合
	DepartmentSet = wire.NewSet(
		dao.NewDepartmentDAO,
		repository.NewDepartmentRepository,
		deptsvc.NewDepartmentService,
		depthdl.NewHandler,
	)

	// GroupSet 用户组治理模块 Provider 集合
	GroupSet = wire.NewSet(
		dao.NewGroupDAO,
		repository.NewGroupRepository,
		groupsvc.NewGroupService,
		grouphdl.NewHandler,
	)

	// InvitationSet 租户成员邀请与审批模块 Provider 集合
	InvitationSet = wire.NewSet(
		dao.NewInvitationDAO,
		repository.NewInvitationRepository,
		invitationsvc.NewInvitationService,
		invitationhdl.NewHandler,
	)

	// ResourceSet 统一资产对账、元数据发现与令牌服务模块 Provider 集合
	ResourceSet = wire.NewSet(
		cache.NewDiscoveryCache,
		cache.NewResourceCache,
		dao.NewResourceDAO,
		dao.NewServiceDAO,
		repository.NewResourceRepository,
		repository.NewServiceRepository,
		resource.NewResourceService,
		resource.NewResourceInitializer,
		ingestion.NewEngine,
		discovery.NewWorker,
		discovery.NewDiscoveryService,
		discovery.NewTokenService,
		discoveryhdl.NewHandler,
	)

	// AuditSet 安全审计流消息队列、缓冲消费与查询模块 Provider 集合
	AuditSet = wire.NewSet(
		dao.NewAuditDAO,
		repository.NewAuditRepository,
		auditevt.NewProducer,
		auditevt.NewConsumer,
		auditsvc.NewService,
		audithdl.NewHandler,
	)

	// WebSet HTTP 中间件、能力注册与 Web 服务装配集合
	WebSet = wire.NewSet(
		InitProviders,
		InitSearchSubjectProviders,
		InitTasks,
		InitGinMiddlewares,
		middleware.NewTenancyBuilder,
		InitGinWebServer,
	)

	// GrpcSet gRPC 内部服务端点装配集合
	GrpcSet = wire.NewSet(
		grpc.NewUserServer,
		grpc.NewTenantServiceServer,
		grpc.NewDepartmentServer,
		InitGrpcServer,
	)

	// TokenCliSet CLI 命令行 Token 生成工具专用轻量 Provider 集合 (仅依赖 DB)
	TokenCliSet = wire.NewSet(
		dao.NewTenantKeyDAO,
		dao.NewServiceDAO,
		repository.NewTenantKeyRepository,
		repository.NewServiceRepository,
		discovery.NewTokenService,
	)

	// IdpSet 统一身份提供商 (IdP / OIDC Provider) 模块 Provider 集合
	IdpSet = wire.NewSet(
		cache.NewOidcCache,
		dao.NewOAuthClientDAO,
		repository.NewOAuthClientRepository,
		idpsvc.NewOAuthClientService,
		idpsvc.NewService,
		InitKeyManager,
		idphdl.NewHandler,
	)
)
