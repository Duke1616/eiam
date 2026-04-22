package user

import (
	"fmt"
	"strconv"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/service/tenant"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ekit/slice"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	capability.IRegistry
	svc       usersvc.IUserService
	tenantSvc tenant.ITenantService
	ldapSvc   usersvc.LdapService
	sp        session.Provider
}

func NewUserHandler(svc usersvc.IUserService, tenantSvc tenant.ITenantService, ldapSvc usersvc.LdapService, sp session.Provider) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "user", "用户管理"),
		svc:       svc,
		tenantSvc: tenantSvc,
		ldapSvc:   ldapSvc,
		sp:        sp,
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/user")
	g.POST("/signup", ginx.B[SignupRequest](h.Signup))
	g.POST("/ldap/login", ginx.B[LoginLdapRequest](h.LoginLdap))
	g.POST("/system/login", ginx.B[LoginSystemRequest](h.LoginSystem))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/user")
	g.GET("/profile", h.Capability("查看个人资料", "profile").
		Handle(ginx.W(h.Profile)),
	)
	g.POST("/logout", h.Capability("退出登录", "logout").
		Handle(ginx.W(h.Logout)),
	)

	g.POST("/password/update", ginx.B[UpdatePasswordRequest](h.UpdatePassword))

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
	g.POST("/list/attached/role", h.Capability("角色关联用户列表", "view").
		Handle(ginx.B[ListRoleUsersRequest](h.ListAttachedRole)),
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
}

func (h *Handler) Signup(ctx *ginx.Context, req SignupRequest) (ginx.Result, error) {
	if req.Password != req.ConfirmPassword {
		return ErrPasswordMismatch, nil
	}

	id, err := h.svc.Signup(ctx.Request.Context(), req.ToDomain())
	if err != nil {
		return ErrSignupFailed, err
	}

	return ginx.Result{Data: id}, nil
}

func (h *Handler) LoginLdap(ctx *ginx.Context, req LoginLdapRequest) (ginx.Result, error) {
	result, err := h.svc.Login(ctx.Request.Context(), "ldap", req.Username, req.Password)
	if err != nil {
		return ErrUnauthorized, err
	}

	return h.handleLoginResult(ctx, result)
}

func (h *Handler) LoginSystem(ctx *ginx.Context, req LoginSystemRequest) (ginx.Result, error) {
	result, err := h.svc.Login(ctx.Request.Context(), "local", req.Username, req.Password)
	if err != nil {
		return ErrUnauthorized, err
	}

	return h.handleLoginResult(ctx, result)
}

// handleLoginResult 统一处理登录后的路由决策
func (h *Handler) handleLoginResult(ctx *ginx.Context, result domain.LoginResult) (ginx.Result, error) {
	if err := h.issueSession(ctx, result.User.ID, result.User.Username,
		strconv.FormatInt(result.TenantID, 10)); err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{
		Msg: fmt.Sprintf("登录成功，欢迎回来：%s", result.User.Username),
		Data: RetrieveUser{
			User:    ToUserVO(result.User),
			Tenants: ToTenantVOs(result.Tenants),
		},
	}, nil
}

func (h *Handler) Profile(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ErrUnauthenticated, err
	}

	uid := sess.Claims().Uid
	u, err := h.svc.GetById(ctx, uid)
	if err != nil {
		return ErrUserNotFound, err
	}

	return ginx.Result{Data: ToUserVO(u)}, nil
}

func (h *Handler) Logout(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ginx.Result{Msg: "已退出登录"}, nil
	}

	if err = sess.Destroy(ctx.Request.Context()); err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "退出登录成功"}, nil
}

// issueSession 统一颁发（或刷新）JWT，tenantID=0 代表临时凭证，等待选择
func (h *Handler) issueSession(ctx *ginx.Context, uid int64, username string, tenantID string) error {
	_, err := session.NewSessionBuilder(ctx, uid).
		SetJwtData(map[string]string{
			"tenant_id": tenantID,
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

	err = h.svc.UpdatePassword(ctx.Request.Context(), uid, req.OldPassword, req.NewPassword)
	if err != nil {
		return ErrUnauthorized, err
	}

	return ginx.Result{Msg: "密码修改成功"}, nil
}

func (h *Handler) List(ctx *ginx.Context, req ListUserRequest) (ginx.Result, error) {
	currentTid := ctxutil.GetTenantID(ctx).Int64()

	// 1. 视角决策：系统管理员在全局页面使用上帝视角 (queryTid=0)，普通管理员锁定当前空间
	queryTid := currentTid
	if currentTid == ctxutil.SystemTenantID {
		queryTid = 0
	}

	// 2. 调用服务层获取数据
	users, total, err := h.svc.List(ctx.Request.Context(), queryTid, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ginx.Result{}, err
	}

	// 3. 视图装饰：如果不是系统管理员，直接返回基础用户信息
	if currentTid != ctxutil.SystemTenantID {
		return ginx.Result{
			Data: RetrieveUsers[User]{
				Total: total,
				Users: slice.Map(users, func(idx int, src domain.User) User {
					return ToUserVO(src)
				}),
			},
		}, nil
	}

	// 4. 超管特权装饰：批量标识这些用户中，哪些已经入驻了当前管理空间（或已入驻任意空间）
	userIDs := slice.Map(users, func(idx int, src domain.User) int64 {
		return src.ID
	})

	// 这里的 FindMembershipsByUserIds 会返回用户与租户的关联关系
	memberMap, _ := h.tenantSvc.FindMembershipsByUserIds(ctx.Request.Context(), userIDs)

	return ginx.Result{
		Data: RetrieveUsers[UserMemberVO]{
			Total: total,
			Users: slice.Map(users, func(idx int, src domain.User) UserMemberVO {
				m, ok := memberMap[src.ID]
				isMember := ok && m.TenantID == currentTid
				return UserMemberVO{
					User:     ToUserVO(src),
					IsMember: &isMember,
				}
			}),
		},
	}, nil
}

func (h *Handler) Update(ctx *ginx.Context, req UpdateUserReq) (ginx.Result, error) {
	_, err := h.svc.Update(ctx.Request.Context(), req.ToDomain())
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

	isMember, err := h.tenantSvc.CheckUserTenantAccess(ctx.Request.Context(), u.ID, tid)
	if err != nil {
		return ginx.Result{}, err
	}

	return ginx.Result{
		Data: UserMemberVO{
			User:     ToUserVO(u),
			IsMember: &isMember,
		},
	}, nil
}

// resolveUser 高效解析用户标识符
func (h *Handler) resolveUser(ctx *ginx.Context) (domain.User, error) {
	// 逻辑：ID 优先 (ID 是物理主键，查询速度最快)
	if id, err := ctx.Query("id").AsInt64(); err == nil && id != 0 {
		return h.svc.GetById(ctx.Request.Context(), id)
	}

	// 降级：使用 Username (支持 username 或 code 参数名)
	if username, err := ctx.Query("username").AsString(); err == nil && username != "" {
		return h.svc.GetByUsername(ctx.Request.Context(), username)
	}

	return domain.User{}, fmt.Errorf("未找到该用户信息")
}

func (h *Handler) Delete(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrUserNotFound, err
	}

	err = h.svc.Delete(ctx.Request.Context(), id)
	if err != nil {
		return ErrUserDeleteFailed, err
	}

	return ginx.Result{Msg: "删除用户成功"}, nil
}

func (h *Handler) ListAttachedRole(ctx *ginx.Context, req ListRoleUsersRequest) (ginx.Result, error) {
	users, total, err := h.svc.GetAttachedUsersWithFilter(ctx.Request.Context(), req.RoleCode, req.Offset, req.Limit, req.Keyword)
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
	users, total, err := h.ldapSvc.SearchCacheUserWithPager(ctx.Request.Context(), req.Keywords, req.Offset, req.Limit)
	if err != nil {
		return ErrLdapSearchFailed, err
	}

	usernames := slice.Map(users, func(idx int, src domain.User) string {
		return src.Username
	})

	existMap, err := h.svc.CheckUsersExist(ctx.Request.Context(), usernames)
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
	users := slice.Map(req.Users, func(idx int, src User) domain.User {
		return src.ToDomain()
	})

	err := h.ldapSvc.Sync(ctx.Request.Context(), users)
	if err != nil {
		return ErrLdapSyncFailed, err
	}

	return ginx.Result{Msg: "同步 LDAP 用户成功"}, nil
}

func (h *Handler) LdapRefreshCache(ctx *ginx.Context) (ginx.Result, error) {
	err := h.ldapSvc.RefreshCacheUserWithPager(ctx.Request.Context())
	if err != nil {
		return ErrLdapRefreshFailed, err
	}

	return ginx.Result{Msg: "刷新 LDAP 缓存成功"}, nil
}
