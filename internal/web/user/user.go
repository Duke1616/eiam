package user

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	idsource "github.com/Duke1616/eiam/internal/service/identity_source"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/tenant"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/internal/service/user/ldap"
	"github.com/Duke1616/eiam/internal/service/user/passkey"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ekit/slice"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/gotomicro/ego/core/elog"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
)

type Handler struct {
	capability.IRegistry
	userSvc    usersvc.IUserService
	tenantSvc  tenant.ITenantService
	ldapSvc    ldap.LdapService
	idsSvc     idsource.IService
	passkeySvc passkey.IPasskeyService
	permSvc    permission.IPermissionService
	sp         session.Provider
	logger     *elog.Component
}

func NewUserHandler(
	userSvc usersvc.IUserService,
	tenantSvc tenant.ITenantService,
	ldapSvc ldap.LdapService,
	idsSvc idsource.IService,
	passkeySvc passkey.IPasskeyService,
	permSvc permission.IPermissionService,
	sp session.Provider,
) *Handler {
	return &Handler{
		IRegistry:  capability.NewRegistry("iam", "user", "用户管理"),
		userSvc:    userSvc,
		tenantSvc:  tenantSvc,
		ldapSvc:    ldapSvc,
		idsSvc:     idsSvc,
		passkeySvc: passkeySvc,
		permSvc:    permSvc,
		sp:         sp,
		logger:     elog.DefaultLogger,
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/user")
	g.POST("/signup", ginx.B[SignupRequest](h.Signup))
	g.POST("/ldap/login", ginx.B[LoginRequest](h.LoginLdap))
	g.POST("/system/login", ginx.B[LoginRequest](h.LoginSystem))
	g.POST("/bind/confirm", ginx.B[BindConfirmRequest](h.BindConfirm))

	// OIDC 授权跳转：未登录用户触发，不需要登录态
	g.GET("/oidc/render", ginx.W(h.OIDCAuthURL))
	// OIDC 回调必须公开：飞书服务器回调时不携带用户登录态
	g.GET("/oidc/callback", ginx.W(h.OIDCCallback))

	// Passkey 登录流程
	g.POST("/passkey/login/start", ginx.W(h.PasskeyLoginStart))
	g.POST("/passkey/login/finish", ginx.W(h.PasskeyLoginFinish))

	// 登录阶段的 MFA 校验
	g.POST("/login/mfa/verify", ginx.B[MfaLoginVerifyRequest](h.LoginMFAVerify))

}

func (h *Handler) IdentityRoutes(server *gin.Engine) {
	g := server.Group("/api/user")
	// 用户基本操作
	g.POST("/password/update", ginx.B[UpdatePasswordRequest](h.UpdatePassword))
	g.GET("/profile", ginx.W(h.Profile))
	g.POST("/logout", ginx.W(h.Logout))

	// Passkey 注册流程 (个人自服务)
	g.POST("/passkey/register/start", ginx.W(h.PasskeyRegisterStart))
	g.POST("/passkey/register/finish", ginx.W(h.PasskeyRegisterFinish))

	// MFA 二次验证 (设置类接口，需登录)
	g.GET("/mfa/totp/setup", ginx.W(h.MfaTotpSetup))
	g.POST("/mfa/totp/bind", ginx.B[MfaTotpBindRequest](h.MfaTotpBind))
	g.POST("/mfa/disable", ginx.W(h.MfaDisable))

	// 当前只是为了前端查询 passkey 的绑定使用
	g.GET("/identity/list", ginx.W(h.ListMyIdentities))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/user")

	g.POST("/create", h.Capability("创建用户", "add").
		Handle(ginx.B[SignupRequest](h.Create)),
	)
	g.POST("/list", h.Capability("用户列表", "view").
		Handle(ginx.B[ListUserRequest](h.List)),
	)
	g.POST("/update", h.Capability("修改用户", "edit").
		Handle(ginx.B[UpdateUserReq](h.Update)),
	)
	// 用户详情：统一入口，智能识别 id 或 username (query 传参)
	g.GET("/detail", h.Capability("用户详情", "get").
		Handle(ginx.W(h.Detail)),
	)
	g.DELETE("/delete/:id", h.Capability("删除用户", "delete").
		Handle(ginx.W(h.Delete)),
	)
	g.POST("/batch_delete", h.Capability("批量删除用户", "batch_delete").
		Handle(ginx.B[BatchDeleteReq](h.BatchDelete)),
	)
	// LDAP 管理接口
	g.POST("/ldap/search", h.Capability("搜索 LDAP", "ldap_search").
		Handle(ginx.B[SearchLdapUser](h.SearchLdapUser)),
	)
	g.POST("/ldap/sync", h.Capability("同步 LDAP", "ldap_sync").
		Handle(ginx.B[SyncLdapUserReq](h.SyncLdapUser)),
	)
	g.POST("/ldap/refresh_cache", h.Capability("刷新 LDAP 缓存", "ldap_refresh").
		Handle(ginx.W(h.LdapRefreshCache)),
	)
	// 绑定、解绑第三方身份，为了做一些消息通知使用
	g.POST("/identity/manage", h.Capability("治理外部身份", "manage_identity").
		Handle(ginx.B[ManageIdentitiesRequest](h.ManageIdentities)),
	)
	g.POST("/identity/unbind", h.Capability("解绑外部身份", "unbind_identity").
		Handle(ginx.B[UnbindIdentityRequest](h.UnbindIdentity)))

	// 查询特定角色关联的用户 (管理侧使用)
	g.POST("/list/attached/role", h.Capability("角色关联用户列表", "view_role_members").
		Module("role").
		Group("角色管理").
		Handle(ginx.B[ListRoleUsersRequest](h.ListAttachedRole)),
	)
}

func (h *Handler) Signup(ctx *ginx.Context, req SignupRequest) (ginx.Result, error) {
	if req.Password != req.ConfirmPassword {
		return ErrPasswordMismatch, nil
	}

	id, err := h.userSvc.Signup(ctx.Request.Context(), req.ToDomain())
	if err != nil {
		return ErrSignupFailed, err
	}

	return ginx.Result{Data: id}, nil
}

func (h *Handler) Create(ctx *ginx.Context, req SignupRequest) (ginx.Result, error) {
	if req.Password != req.ConfirmPassword {
		return ErrPasswordMismatch, nil
	}

	// 1. 调用 Service 创建用户
	id, err := h.userSvc.Signup(ctx.Request.Context(), req.ToDomain())
	if err != nil {
		return ErrSignupFailed, err
	}

	// 2. 如果是租户管理员（非系统租户）创建，则自动将该用户关联至当前租户
	tid := ctxutil.GetTenantID(ctx).Int64()
	if tid != ctxutil.SystemTenantID {
		err = h.tenantSvc.AssignUser(ctx.Request.Context(), id)
		if err != nil {
			h.logger.Error("管理员创建用户后自动分配租户失败",
				elog.Int64("uid", id),
				elog.Int64("tid", tid),
				elog.FieldErr(err),
			)
		}
	}

	return ginx.Result{
		Data: id,
		Msg:  "用户主体创建成功",
	}, nil
}

func (h *Handler) LoginLdap(ctx *ginx.Context, req LoginRequest) (ginx.Result, error) {
	return h.executeLogin(ctx, "ldap", req.Username, req.Password)
}

func (h *Handler) LoginSystem(ctx *ginx.Context, req LoginRequest) (ginx.Result, error) {
	return h.executeLogin(ctx, "local", req.Username, req.Password)
}

func (h *Handler) executeLogin(ctx *ginx.Context, provider, username, password string) (ginx.Result, error) {
	result, err := h.userSvc.Login(ctx.Request.Context(), provider, username, password)
	if err != nil {
		return ErrUnauthorized, err
	}

	return h.handleLoginResult(ctx, result)
}

// BindConfirm 接收显式的账户绑定确认请求，保证常规登录流程的职责纯粹与高安全性
func (h *Handler) BindConfirm(ctx *ginx.Context, req BindConfirmRequest) (ginx.Result, error) {
	// 1. 验证常规系统身份登录，确保密码匹配
	result, err := h.userSvc.Login(ctx.Request.Context(), "local", req.Username, req.Password)
	if err != nil {
		return ErrUnauthorized, err
	}

	// 2. 验证成功后，消费绑定令牌完成外部账号关联
	err = h.userSvc.ConsumeBindToken(ctx.Request.Context(), result.User.ID, req.BindToken)
	if err != nil {
		return ErrBindFailed, err
	}

	h.logger.Info("用户显式确认并自动完成第三方身份绑定", elog.Int64("uid", result.User.ID))

	// 3. 统一签发 Session
	return h.handleLoginResult(ctx, result)
}

// handleLoginResult 统一处理登录后的路由决策
func (h *Handler) handleLoginResult(ctx *ginx.Context, result domain.LoginResult) (ginx.Result, error) {
	// 如果需要 MFA，则不签发正式 Session，直接返回 MFA 令牌
	if result.MfaRequired {
		return ginx.Result{
			Msg: "请进行二次验证",
			Data: RetrieveUser{
				User:            ToUserVO(result.User),
				MfaRequired:     true,
				MfaToken:        result.MfaToken,
				CurrentTenantID: result.TenantID,
			},
		}, nil
	}

	if err := h.issueSession(ctx, result.User.ID, result.User.Username, result.TenantID); err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{
		Msg: fmt.Sprintf("登录成功，欢迎回来：%s", result.User.Username),
		Data: RetrieveUser{
			User:             ToUserVO(result.User),
			Tenants:          ToTenantVOs(result.Tenants),
			CurrentTenantID:  result.TenantID,
			MustSelectTenant: result.MustSelectTenant,
			MustBind:         result.MustBind,
			BindToken:        result.BindToken,
		},
	}, nil
}

// OIDCAuthURL 引导用户重定向至 OIDC 提供商 (如飞书)
func (h *Handler) OIDCAuthURL(ctx *ginx.Context) (ginx.Result, error) {
	providerType, err := ctx.Query("provider_type").AsString()
	if err != nil || providerType == "" {
		return ErrInvalidInput, fmt.Errorf("provider_type 不能为空")
	}

	h.logger.Info("[OIDC] 获取授权 URL", elog.String("provider_type", providerType))

	url, err := h.idsSvc.GetAuthURL(ctx.Request.Context(), providerType)
	if err != nil {
		h.logger.Error("[OIDC] 获取授权 URL 失败", elog.FieldErr(err))
		return ErrInternalServer, err
	}

	h.logger.Info("[OIDC] 授权 URL 生成成功", elog.String("url", url))
	return ginx.Result{Data: url}, nil
}

// OIDCCallback 处理 OIDC 授权码回调
func (h *Handler) OIDCCallback(ctx *ginx.Context) (ginx.Result, error) {
	//  OAuth2 授权被拒绝时，提供商会在回调中携带 error 参数
	if errParam, _ := ctx.Query("error").AsString(); errParam != "" {
		desc, _ := ctx.Query("error_description").AsString()
		h.logger.Warn("[OIDC] 授权被拒绝", elog.String("error", errParam), elog.String("desc", desc))
		return ErrOIDCDenied, fmt.Errorf("OIDC 授权被拒绝: %s - %s", errParam, desc)
	}

	code, _ := ctx.Query("code").AsString()
	state, _ := ctx.Query("state").AsString()

	if code == "" || state == "" {
		return ErrInvalidInput, fmt.Errorf("OIDC 回调缺少必要参数: code 或 state 为空")
	}

	h.logger.Info("[OIDC] 收到回调", elog.Int("code_len", len(code)), elog.String("state", state))

	// 1. 校验并获取身份信息
	ident, err := h.idsSvc.VerifyOIDC(ctx.Request.Context(), state, code)
	if err != nil {
		h.logger.Error("[OIDC] 身份校验失败", elog.FieldErr(err))
		return ErrInternalServer, err
	}

	h.logger.Info("[OIDC] 身份校验成功",
		elog.String("provider", ident.Provider),
		elog.String("external_id", ident.ExternalID),
		elog.String("username", ident.Username),
	)

	// 2. 执行登录与 JIT 开户
	result, err := h.userSvc.LoginWithExternal(ctx.Request.Context(), ident, true)
	if err != nil {
		// 如果是未绑定且禁用了 JIT，则走“登录页绑定”流程
		if errors.Is(err, errs.ErrUserNotLinked) {
			token, tokenErr := h.userSvc.GenerateBindToken(ctx.Request.Context(), ident)
			if tokenErr != nil {
				return ErrInternalServer, tokenErr
			}
			return ginx.Result{
				Code: 0,
				Msg:  "请先登录现有账号完成绑定",
				Data: RetrieveUser{
					MustBind:  true,
					BindToken: token,
				},
			}, nil
		}
		h.logger.Error("[OIDC] 登录处理失败", elog.FieldErr(err))
		return ErrInternalServer, err
	}

	h.logger.Info("[OIDC] 登录成功",
		elog.Int64("user_id", result.User.ID),
		elog.String("username", result.User.Username),
		elog.Int64("tenant_id", result.TenantID),
		elog.Int("tenant_count", len(result.Tenants)),
	)

	// 3. 复用统一的登录处理逻辑
	return h.handleLoginResult(ctx, result)
}

func (h *Handler) Profile(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ErrUnauthenticated, err
	}

	uid := sess.Claims().Uid
	var (
		eg      errgroup.Group
		u       domain.User
		tenants []domain.Tenant
	)

	// 并发获取用户信息和租户列表
	eg.Go(func() error {
		u, err = h.userSvc.GetById(ctx.Request.Context(), uid)
		return err
	})

	eg.Go(func() error {
		tenants, err = h.tenantSvc.GetTenantsByUserId(ctx.Request.Context(), uid)
		return err
	})

	if err = eg.Wait(); err != nil {
		return ErrUserNotFound, err
	}

	tenantID, _ := sess.Get(ctx.Request.Context(), "tenant_id").AsInt64()
	roles, _ := h.permSvc.GetRolesForUser(ctx.Request.Context(), u.Username)
	permissions, _ := h.permSvc.GetAuthorizedCodes(ctx.Request.Context(), u.Username)

	return ginx.Result{
		Data: RetrieveUser{
			User:            ToUserVO(u),
			Tenants:         ToTenantVOs(tenants),
			CurrentTenantID: tenantID,
			IsAdmin:         domain.HasAdminRole(roles),
			Permissions:     permissions,
		},
	}, nil
}

func (h *Handler) Logout(ctx *ginx.Context) (ginx.Result, error) {
	if _, err := session.Get(ctx); err != nil {
		return ginx.Result{Msg: "已退出登录"}, nil
	}

	if err := h.sp.Destroy(ctx); err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "退出登录成功"}, nil
}

// issueSession 统一颁发（或刷新）JWT，tenantID=0 代表临时凭证，等待选择
func (h *Handler) issueSession(ctx *ginx.Context, uid int64, username string, tenantID int64) error {
	_, err := session.NewSessionBuilder(ctx, uid).
		SetJwtData(map[string]string{
			"tenant_id": strconv.FormatInt(tenantID, 10),
			"username":  username,
		}).
		SetSessData(map[string]any{
			"username":  username,
			"tenant_id": tenantID,
		}).
		Build()

	return err
}

func (h *Handler) UpdatePassword(ctx *ginx.Context, req UpdatePasswordRequest) (ginx.Result, error) {
	if req.NewPassword != req.ConfirmPassword {
		return ErrPasswordMismatch, nil
	}

	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ErrUnauthenticated, err
	}

	uid := sess.Claims().Uid

	err = h.userSvc.UpdatePassword(ctx.Request.Context(), uid, req.OldPassword, req.NewPassword)
	if err != nil {
		return ErrUnauthorized, err
	}

	return ginx.Result{Msg: "密码修改成功"}, nil
}

func (h *Handler) List(ctx *ginx.Context, req ListUserRequest) (ginx.Result, error) {
	// 获取基础用户列表
	users, total, err := h.fetchUsers(ctx, req)
	if err != nil {
		return ginx.Result{}, err
	}

	currentTid := ctxutil.GetTenantID(ctx).Int64()

	// 非系统管理员直接返回基础用户信息
	if currentTid != ctxutil.SystemTenantID {
		return ginx.Result{
			Data: RetrieveUsers[User]{
				Total: total,
				Users: toUserVOs(users),
			},
		}, nil
	}

	// 系统管理员：装饰成员信息
	userIDs := slice.Map(users, func(idx int, u domain.User) int64 { return u.ID })
	memberMap, _ := h.tenantSvc.CheckUsersInTenant(ctx.Request.Context(), userIDs)

	return ginx.Result{
		Data: RetrieveUsers[UserMemberVO]{
			Total: total,
			Users: toUserMemberVOs(users, memberMap),
		},
	}, nil
}

// ----------- 辅助函数 --------------

func (h *Handler) fetchUsers(ctx *ginx.Context, req ListUserRequest) ([]domain.User, int64, error) {
	if req.Usernames != nil {
		users, err := h.userSvc.GetByUsernames(ctx, req.Usernames)
		if err != nil {
			return nil, 0, err
		}
		return users, int64(len(users)), nil
	}

	return h.userSvc.List(ctx.Request.Context(), req.Offset, req.Limit, req.Keyword)
}

func toUserVOs(users []domain.User) []User {
	return slice.Map(users, func(idx int, u domain.User) User {
		return ToUserVO(u)
	})
}

func toUserMemberVOs(users []domain.User, memberMap map[int64]bool) []UserMemberVO {
	return slice.Map(users, func(idx int, u domain.User) UserMemberVO {
		isMember := memberMap[u.ID]
		return UserMemberVO{
			User:     ToUserVO(u),
			IsMember: &isMember,
		}
	})
}

func (h *Handler) Update(ctx *ginx.Context, req UpdateUserReq) (ginx.Result, error) {
	_, err := h.userSvc.Update(ctx.Request.Context(), req.ToDomain())
	if err != nil {
		return ErrUserUpdateFailed, err
	}
	return ginx.Result{Msg: "更新用户信息成功"}, nil
}

func (h *Handler) Detail(ctx *ginx.Context) (ginx.Result, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()

	// 1. 优雅地解析用户实体 (支持 ID 或 Username)
	u, err := h.resolveUser(ctx)
	if err != nil {
		return ErrUserNotFound, err
	}

	isMember, err := h.tenantSvc.CheckUserTenantAccess(ctx.Request.Context(), u.ID)
	if err != nil {
		return ginx.Result{}, err
	}

	return ginx.Result{
		Data: UserMemberVO{
			User:          ToUserVO(u),
			IsMember:      &isMember,
			IsSystemSpace: tid == ctxutil.SystemTenantID,
		},
	}, nil
}

// resolveUser 高效解析用户标识符
func (h *Handler) resolveUser(ctx *ginx.Context) (domain.User, error) {
	// 逻辑：ID 优先 (ID 是物理主键，查询速度最快)
	if id, err := ctx.Query("id").AsInt64(); err == nil && id != 0 {
		return h.userSvc.GetById(ctx.Request.Context(), id)
	}

	// 降级：使用 Username (支持 username 或 code 参数名)
	if username, err := ctx.Query("username").AsString(); err == nil && username != "" {
		return h.userSvc.GetByUsername(ctx.Request.Context(), username)
	}

	return domain.User{}, fmt.Errorf("未找到该用户信息")
}

func (h *Handler) Delete(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrUserNotFound, err
	}

	err = h.userSvc.Delete(ctx.Request.Context(), id)
	if err != nil {
		return ErrUserDeleteFailed, err
	}

	return ginx.Result{Msg: "删除用户成功"}, nil
}

func (h *Handler) BatchDelete(ctx *ginx.Context, req BatchDeleteReq) (ginx.Result, error) {
	if _, err := h.userSvc.BatchDelete(ctx.Request.Context(), req.IDs); err != nil {
		return ErrUserDeleteFailed, err
	}

	return ginx.Result{Msg: "批量删除用户成功"}, nil
}

func (h *Handler) ListAttachedRole(ctx *ginx.Context, req ListRoleUsersRequest) (ginx.Result, error) {
	users, total, err := h.userSvc.GetAttachedUsersWithFilter(ctx.Request.Context(), req.RoleCode, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrUserListFailed, err
	}

	return ginx.Result{
		Data: RetrieveUsers[User]{
			Total: total,
			Users: slice.Map(users, func(idx int, src domain.User) User {
				return ToUserVO(src)
			}),
		},
	}, nil
}

func (h *Handler) SearchLdapUser(ctx *ginx.Context, req SearchLdapUser) (ginx.Result, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	users, total, err := h.ldapSvc.SearchCacheUserWithPager(ctx.Request.Context(), tid, req.Keywords, req.Offset, req.Limit)
	if err != nil {
		return ErrLdapSearchFailed, err
	}

	usernames := slice.Map(users, func(idx int, src domain.User) string {
		return src.Username
	})

	existMap, err := h.userSvc.CheckUsersExist(ctx.Request.Context(), usernames)
	if err != nil {
		existMap = make(map[string]bool) // 如果检查失败，默认都不存在，或者根据需求返回 Error
	}

	return ginx.Result{
		Data: LdapUserList{
			Total: int64(total),
			Users: slice.Map(users, func(idx int, src domain.User) LdapSyncUser {
				return LdapSyncUser{
					User:     ToUserVO(src),
					IsSynced: existMap[src.Username],
				}
			}),
		},
	}, nil
}

func (h *Handler) SyncLdapUser(ctx *ginx.Context, req SyncLdapUserReq) (ginx.Result, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	users := slice.Map(req.Users, func(idx int, src User) domain.User {
		return src.ToDomain()
	})

	err := h.ldapSvc.Sync(ctx.Request.Context(), tid, users)
	if err != nil {
		return ErrLdapSyncFailed, err
	}

	return ginx.Result{Msg: "同步 LDAP 用户成功"}, nil
}

func (h *Handler) LdapRefreshCache(ctx *ginx.Context) (ginx.Result, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	err := h.ldapSvc.RefreshCacheUserWithPager(ctx.Request.Context(), tid)
	if err != nil {
		return ErrLdapRefreshFailed, err
	}

	return ginx.Result{Msg: "刷新 LDAP 缓存成功"}, nil
}

func (h *Handler) BindIdentity(ctx *ginx.Context, req BindIdentityRequest) (ginx.Result, error) {
	err := h.userSvc.BindIdentity(ctx.Request.Context(), req.UserID, req.ToDomain())
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "绑定身份成功"}, nil
}

func (h *Handler) UnbindIdentity(ctx *ginx.Context, req UnbindIdentityRequest) (ginx.Result, error) {
	err := h.userSvc.UnbindIdentity(ctx.Request.Context(), req.UserID, req.Provider, req.IdentityID)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "解除绑定成功"}, nil
}

func (h *Handler) ManageIdentities(ctx *ginx.Context, req ManageIdentitiesRequest) (ginx.Result, error) {
	identities := []domain.UserIdentity{
		{Provider: "ldap", LdapInfo: domain.LdapInfo(req.LdapInfo)},
		{Provider: "wechat", WechatInfo: domain.WechatInfo(req.WechatInfo)},
		{Provider: "feishu", FeishuInfo: domain.FeishuInfo(req.FeishuInfo)},
	}

	err := h.userSvc.ManageIdentities(ctx.Request.Context(), req.UserID, identities)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "外部身份治理信息已更新"}, nil
}

// PasskeyRegisterStart 获取 Passkey 注册挑战 (Challenge)
func (h *Handler) PasskeyRegisterStart(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return ErrInternalServer, err
	}

	u, err := h.userSvc.GetById(ctx.Request.Context(), sess.Claims().Uid)
	if err != nil {
		return ErrInternalServer, err
	}

	options, sessionData, err := h.passkeySvc.BeginRegistration(ctx.Request.Context(), u)
	if err != nil {
		return ErrInternalServer, err
	}

	token := uuid.New().String()
	err = h.userSvc.SetPasskeyState(ctx.Request.Context(), token, *sessionData)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Data: map[string]any{
		"options":       options,
		"session_token": token,
	}}, nil
}

// PasskeyRegisterFinish 验证并完成 Passkey 绑定
func (h *Handler) PasskeyRegisterFinish(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return ErrInternalServer, err
	}

	u, err := h.userSvc.GetById(ctx.Request.Context(), sess.Claims().Uid)
	if err != nil {
		return ErrInternalServer, err
	}

	token := ctx.GetHeader("X-Passkey-Session")
	if token == "" {
		return ErrInvalidInput, fmt.Errorf("请求头缺少 X-Passkey-Session")
	}

	sessionData, err := h.userSvc.GetPasskeyState(ctx.Request.Context(), token)
	if err != nil {
		return ErrInternalServer, fmt.Errorf("注册会话已过期或不存在")
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponse(ctx.Request)
	if err != nil {
		return ErrInvalidInput, err
	}

	err = h.passkeySvc.FinishRegistration(ctx.Request.Context(), u, sessionData, parsedResponse)
	if err != nil {
		return ErrUnauthorized, err
	}

	return ginx.Result{Msg: "Passkey 注册成功"}, nil
}

// PasskeyLoginStart 获取 Passkey 登录挑战
func (h *Handler) PasskeyLoginStart(ctx *ginx.Context) (ginx.Result, error) {
	sources, err := h.idsSvc.List(ctx.Request.Context())
	if err != nil {
		return ErrInternalServer, err
	}

	config, found := slice.Find(sources, func(src domain.IdentitySource) bool {
		return src.Type == domain.PASSKEY && src.Enabled
	})
	if !found {
		return ErrInternalServer, fmt.Errorf("Passkey 身份源未启用")
	}

	options, sessionData, err := h.passkeySvc.BeginLogin(ctx.Request.Context(), config)
	if err != nil {
		return ErrInternalServer, err
	}

	token := uuid.New().String()
	err = h.userSvc.SetPasskeyState(ctx.Request.Context(), token, *sessionData)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Data: map[string]any{
		"options":       options,
		"session_token": token,
	}}, nil
}

// PasskeyLoginFinish 验证 Passkey 签名并执行登录
func (h *Handler) PasskeyLoginFinish(ctx *ginx.Context) (ginx.Result, error) {
	token := ctx.GetHeader("X-Passkey-Session")
	if token == "" {
		return ErrInvalidInput, fmt.Errorf("请求头缺少 X-Passkey-Session")
	}

	sessionData, err := h.userSvc.GetPasskeyState(ctx.Request.Context(), token)
	if err != nil {
		return ErrInternalServer, fmt.Errorf("登录会话已过期或不存在")
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(ctx.Request)
	if err != nil {
		return ErrInvalidInput, err
	}

	u, err := h.passkeySvc.FinishLogin(ctx.Request.Context(), sessionData, parsedResponse)
	if err != nil {
		return ErrUnauthorized, err
	}

	result, err := h.userSvc.LoginWithoutPassword(ctx.Request.Context(), u.ID, false)
	if err != nil {
		return ErrInternalServer, err
	}

	return h.handleLoginResult(ctx, result)
}

// ListMyIdentities 获取当前用户绑定的身份列表 (支持按 provider 过滤)
func (h *Handler) ListMyIdentities(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ErrUnauthenticated, err
	}

	provider, _ := ctx.Query("provider").AsString()
	uis, err := h.userSvc.ListIdentitiesByUserID(ctx.Request.Context(), sess.Claims().Uid, provider)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{
		Data: lo.Map(uis, func(id domain.UserIdentity, _ int) IdentityVo {
			return IdentityVo{
				Provider:   id.Provider,
				IdentityID: id.IdentityID,
				PasskeyInfo: PasskeyInfo{
					SignCount:      id.PasskeyInfo.SignCount,
					BackupEligible: id.PasskeyInfo.BackupEligible,
					BackupState:    id.PasskeyInfo.BackupState,
					Nickname:       id.PasskeyInfo.Nickname,
				},
			}
		}),
	}, nil
}

func (h *Handler) MfaTotpSetup(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return ErrInternalServer, err
	}

	secret, qrcodeURL, err := h.userSvc.GenerateTOTPSetup(ctx.Request.Context(), sess.Claims().Uid)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{
		Data: MfaTotpSetupResponse{
			Secret:    secret,
			QRCodeURL: qrcodeURL,
		},
	}, nil
}

func (h *Handler) MfaTotpBind(ctx *ginx.Context, req MfaTotpBindRequest) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return ErrInternalServer, err
	}

	err = h.userSvc.VerifyAndEnableTOTP(ctx.Request.Context(), sess.Claims().Uid, req.Code, req.Secret)
	if err != nil {
		return ginx.Result{Code: 400, Msg: err.Error()}, nil
	}

	return ginx.Result{Msg: "MFA 开启成功"}, nil
}

func (h *Handler) MfaDisable(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return ErrInternalServer, err
	}

	err = h.userSvc.DisableMFA(ctx.Request.Context(), sess.Claims().Uid)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "MFA 已关闭"}, nil
}

func (h *Handler) LoginMFAVerify(ctx *ginx.Context, req MfaLoginVerifyRequest) (ginx.Result, error) {
	result, err := h.userSvc.VerifyLoginMFA(ctx.Request.Context(), req.MfaToken, req.Code)
	if err != nil {
		if errors.Is(err, usersvc.ErrMfaAttemptsExhausted) || errors.Is(err, usersvc.ErrMfaTokenNotFound) {
			return ErrMfaTokenInvalid, nil
		}
		return ginx.Result{Code: 401, Msg: err.Error()}, nil
	}

	return h.handleLoginResult(ctx, result)
}
