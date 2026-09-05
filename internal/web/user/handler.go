package user

import (
	idsource "github.com/Duke1616/eiam/internal/service/identity_source"
	permsvc "github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/tenant"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/internal/service/user/ldap"
	"github.com/Duke1616/eiam/internal/service/user/passkey"
	"github.com/Duke1616/eiam/pkg/contract/model"
	"github.com/Duke1616/eiam/pkg/contract/permission"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
)

type Handler struct {
	capability.IRegistry
	userSvc     usersvc.IUserService
	coordinator usersvc.IAuthCoordinator
	tenantSvc   tenant.ITenantService
	ldapSvc     ldap.ILdapService
	idsSvc      idsource.IService
	passkeySvc  passkey.IPasskeyService
	permSvc     permsvc.IPermissionService
	logger      *elog.Component
}

func NewUserHandler(
	userSvc usersvc.IUserService,
	coordinator usersvc.IAuthCoordinator,
	tenantSvc tenant.ITenantService,
	ldapSvc ldap.ILdapService,
	idsSvc idsource.IService,
	passkeySvc passkey.IPasskeyService,
	permSvc permsvc.IPermissionService,
) *Handler {
	return &Handler{
		IRegistry:   capability.NewRegistry("iam", "user", "用户管理"),
		userSvc:     userSvc,
		coordinator: coordinator,
		tenantSvc:   tenantSvc,
		ldapSvc:     ldapSvc,
		idsSvc:      idsSvc,
		passkeySvc:  passkeySvc,
		permSvc:     permSvc,
		logger:      elog.DefaultLogger,
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/user")
	g.POST("/signup", ginx.B[SignupRequest](h.Signup))
	g.POST("/ldap/login", ginx.B[LoginRequest](h.LoginLdap))
	g.POST("/system/login", ginx.B[LoginRequest](h.LoginSystem))
	g.POST("/bind/confirm", ginx.B[BindConfirmRequest](h.BindConfirm))

	// OIDC 授权跳转与公开回调
	g.GET("/oidc/render", ginx.W(h.OIDCAuthURL))
	g.GET("/oidc/callback", ginx.W(h.OIDCCallback))

	// Passkey 登录流程
	g.POST("/passkey/login/start", ginx.W(h.PasskeyLoginStart))
	g.POST("/passkey/login/finish", ginx.W(h.PasskeyLoginFinish))

	// 登录阶段 MFA 验证
	g.POST("/login/mfa/verify", ginx.B[MfaLoginVerifyRequest](h.LoginMFAVerify))
}

func (h *Handler) IdentityRoutes(server *gin.Engine) {
	g := server.Group("/api/user")
	g.POST("/password/update", ginx.BS[UpdatePasswordRequest](h.UpdatePassword))
	g.GET("/profile", h.Define("个人信息", "profile").
		Scope(capability.ScopeTenant).NoSync().NoAudit().
		Bind(ginx.S(h.Profile)),
	)
	g.POST("/logout", h.Define("退出登录", "logout").
		Scope(capability.ScopeTenant).NoSync().NoAudit().
		Bind(ginx.S(h.Logout)),
	)

	// Passkey 个人自服务
	g.POST("/passkey/register/start", ginx.S(h.PasskeyRegisterStart))
	g.POST("/passkey/register/finish", ginx.S(h.PasskeyRegisterFinish))

	// MFA 二次验证
	g.GET("/mfa/totp/setup", ginx.S(h.MfaTotpSetup))
	g.POST("/mfa/totp/bind", ginx.BS[MfaTotpBindRequest](h.MfaTotpBind))
	g.POST("/mfa/disable", ginx.S(h.MfaDisable))

	// 用户绑定的第三方凭证
	g.GET("/identity/list", ginx.S(h.ListMyIdentities))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/user")

	// 1. 基础用户能力与路由装载
	g.POST("/create", h.Define("创建用户", "add").
		Bind(ginx.B[SignupRequest](h.Create)),
	)
	g.POST("/update", h.Define("修改用户", "edit").
		Needs(permission.User.Get).
		Bind(ginx.B[UpdateUserReq](h.Update)),
	)
	g.DELETE("/delete/:id", h.Define("删除用户", "delete").
		Bind(ginx.W(h.Delete)),
	)
	g.POST("/batch_delete", h.Define("批量删除用户", "batch_delete").
		Bind(ginx.B[BatchDeleteReq](h.BatchDelete)),
	)

	// 列表与详情属于不同细粒度权限：view 为列表权限，get 为单体详情权限
	g.POST("/list", h.Define("用户列表", "view").
		Bind(ginx.B[ListUserRequest](h.List)),
	)
	g.GET("/detail", h.Define("用户详情", "get").
		Bind(ginx.W(h.Detail)),
	)

	// 2. LDAP 目录管理能力 (作为用户领域的子功能命名空间派生，分组自动级联拼接为 "用户管理/LDAP管理")
	ldapManager := h.Sub("ldap", "LDAP管理")
	g.POST("/ldap/search", ldapManager.Define("搜索 LDAP", "search").
		Bind(ginx.B[SearchLdapUser](h.SearchLdapUser)),
	)
	g.POST("/ldap/sync", ldapManager.Define("同步 LDAP", "sync").
		Bind(ginx.B[SyncLdapUserReq](h.SyncLdapUser)),
	)
	g.POST("/ldap/refresh_cache", ldapManager.Define("刷新 LDAP 缓存", "refresh").
		Bind(ginx.W(h.LdapRefreshCache)),
	)

	// 3. 外部身份治理
	g.POST("/identity/manage", h.Define("治理外部身份", "manage_identity").
		Bind(ginx.B[ManageIdentitiesRequest](h.ManageIdentities)),
	)
	g.POST("/identity/unbind", h.Define("解绑外部身份", "unbind_identity").
		Bind(ginx.B[UnbindIdentityRequest](h.UnbindIdentity)),
	)

	// 4. 跨业务领域：角色关联用户 (直接使用纯契约 model.Role)
	g.POST("/list/attached/role", h.For(model.Role).Define("角色关联用户列表", "view_role_members").
		Bind(ginx.B[ListRoleUsersRequest](h.ListAttachedRole)),
	)
}
