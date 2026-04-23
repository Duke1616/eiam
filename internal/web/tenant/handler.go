package tenant

import (
	"fmt"
	"strconv"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ekit/slice"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	capability.IRegistry
	svc     tenant.ITenantService
	permSvc permission.IPermissionService
	sess    session.Provider
}

func NewHandler(svc tenant.ITenantService, permSvc permission.IPermissionService, sess session.Provider) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "tenant", "租户管理"),
		svc:       svc,
		permSvc:   permSvc,
		sess:      sess,
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/tenant")
	// 租户空间创建
	g.POST("/create", h.Capability("创建租户空间", "add").
		Handle(ginx.BS[CreateTenantReq](h.CreateTenant)),
	)
	// 获取我所属的所有租户列表 (用于下拉框展示)
	g.GET("/list/mine", h.Capability("查询我的租户列表", "view_mine").
		Handle(ginx.W(h.ListMyTenants)),
	)
	// 【核心：租户上下文切换】
	g.POST("/switch", h.Capability("切换租户空间", "switch").
		Handle(ginx.B[SwitchTenantReq](h.SwitchTenant)),
	)
	// 租户管理 (全量列表/更新/删除/详情)
	g.POST("/list", h.Capability("全量租户列表", "view").
		Handle(ginx.B[ListTenantReq](h.ListTenants)),
	)
	g.POST("/update", h.Capability("修改租户信息", "edit").
		Handle(ginx.B[UpdateTenantReq](h.UpdateTenant)),
	)
	g.DELETE("/delete/:id", h.Capability("删除租户空间", "delete").
		Handle(ginx.W(h.DeleteTenant)),
	)
	g.GET("/detail/:id", h.Capability("查看租户详情", "get").
		Handle(ginx.W(h.Detail)),
	)
	// 查询特定用户的关联租户 (管理侧使用)
	g.POST("/list/attached/user", h.Capability("查询用户所属租户", "view_user_tenants").
		Handle(ginx.BS[ListUserTenantsReq](h.GetTenantsByUserId)),
	)
	// 租户成员管理
	g.POST("/members", h.Capability("查看租户成员", "view_members").
		Handle(ginx.B[ListMembersReq](h.ListMembers)),
	)
	g.POST("/assign", h.Capability("加入租户", "assign").
		Handle(ginx.B[AssignUserReq](h.AssignUser)),
	)
}

func (h *Handler) ListMembers(ctx *ginx.Context, req ListMembersReq) (ginx.Result, error) {
	users, total, err := h.svc.ListMembers(ctx.Context, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrTenantGet, err
	}

	return ginx.Result{
		Data: ListMembersRes{
			Total: total,
			Members: slice.Map(users, func(idx int, u domain.User) MemberVO {
				return MemberVO{
					ID:          u.ID,
					Username:    u.Username,
					Nickname:    u.Profile.Nickname,
					Avatar:      u.Profile.Avatar,
					Email:       u.Email,
					Status:      int(u.Status),
					JobTitle:    u.Profile.JobTitle,
					LastLoginAt: u.LastLoginAt,
					Ctime:       u.Ctime,
				}
			}),
		},
	}, nil
}

func (h *Handler) AssignUser(ctx *ginx.Context, req AssignUserReq) (ginx.Result, error) {
	newCtx := ctxutil.WithTenantID(ctx.Context, req.TenantID)
	err := h.svc.AssignUser(newCtx, req.UserID)
	if err != nil {
		return ErrTenantUpdate, err
	}

	return ginx.Result{
		Msg: "分配用户到租户成功",
	}, nil
}

// CreateTenant 允许用户主动创建一个属于自己的企业/工作空间
func (h *Handler) CreateTenant(ctx *ginx.Context, req CreateTenantReq, sess session.Session) (ginx.Result, error) {
	username, ok := sess.Claims().Data["username"]
	if !ok {
		return ErrUnauthenticated, fmt.Errorf("session 中缺失用户名信息")
	}

	tenantId, err := h.svc.CreateTenant(ctx.Request.Context(), req.Name, req.Code, username, sess.Claims().Uid)
	if err != nil {
		return ErrTenantCreate, err
	}

	// 初始化租户权限：给创建者分配 admin 角色
	newCtx := ctxutil.WithTenantID(ctx.Context, tenantId)
	_, err = h.permSvc.AssignRoleToUser(newCtx, username, "admin")
	if err != nil {
		fmt.Printf("租户创建者授权失败: %v\n", err)
	}

	return ginx.Result{
		Data: tenantId,
		Msg:  "企业租户空间创建成功",
	}, nil
}

// ListMyTenants 获取当前登录用户可操作的所有租户列表
func (h *Handler) ListMyTenants(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := h.sess.Get(&gctx.Context{Context: ctx.Context})
	if err != nil {
		return ErrUnauthorized, err
	}

	// 从服务层获取该用户的所有租户映射
	tenants, err := h.svc.GetTenantsByUserId(ctx.Context, sess.Claims().Uid)
	if err != nil {
		return ErrTenantList, err
	}

	return ginx.Result{
		Data: ToTenantVOs(tenants),
	}, nil
}

// SwitchTenant 实现“租户上下文动态录入”
func (h *Handler) SwitchTenant(ctx *ginx.Context, req SwitchTenantReq) (ginx.Result, error) {
	sess, err := h.sess.Get(&gctx.Context{Context: ctx.Context})
	if err != nil {
		return ErrUnauthorized, err
	}

	// 1. 安全校验：确认该用户是否真的属于目标租户
	hasAccess, err := h.svc.CheckUserTenantAccess(ctx.Context, sess.Claims().Uid, req.TenantID)
	if err != nil || !hasAccess {
		return ErrTenantAccess, nil
	}

	// 2. 【核心录入点】：重新构建 Session 并注入新的租户 ID
	jwtData := map[string]string{
		"tenant_id": strconv.FormatInt(req.TenantID, 10),
		"username":  sess.Claims().Data["username"],
	}

	// 重新 Build Session (Renew Token with new identity)
	// 原 session 框架会重新签发包含了租户信息的 JWT 给前端
	_, err = session.NewSessionBuilder(&gctx.Context{Context: ctx.Context}, sess.Claims().Uid).
		SetJwtData(jwtData).
		Build()

	if err != nil {
		return ErrTenantSwitch, err
	}

	return ginx.Result{
		Msg: "成功切换至新租户空间",
	}, nil
}

func (h *Handler) ListTenants(ctx *ginx.Context, req ListTenantReq) (ginx.Result, error) {
	tenants, total, err := h.svc.List(ctx.Context, req.Offset, req.Limit)
	if err != nil {
		return ErrTenantList, err
	}

	return ginx.Result{
		Data: ListTenantRes{
			Total:   total,
			Tenants: ToTenantVOs(tenants),
		},
	}, nil
}

func (h *Handler) UpdateTenant(ctx *ginx.Context, req UpdateTenantReq) (ginx.Result, error) {
	err := h.svc.Update(ctx.Context, domain.Tenant{
		ID:     req.ID,
		Name:   req.Name,
		Code:   req.Code,
		Domain: req.Domain,
		Status: req.Status,
	})
	if err != nil {
		return ErrTenantUpdate, err
	}

	return ginx.Result{Msg: "更新租户空间信息成功"}, nil
}

func (h *Handler) DeleteTenant(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrTenantDelete, err
	}

	err = h.svc.Delete(ctx.Context, id)
	if err != nil {
		return ErrTenantDelete, err
	}

	return ginx.Result{Msg: "删除租户空间成功"}, nil
}

func (h *Handler) Detail(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrTenantGet, err
	}

	t, err := h.svc.GetByID(ctx.Context, id)
	if err != nil {
		return ErrTenantGet, err
	}

	return ginx.Result{
		Data: ToTenantVO(t),
	}, nil
}

func (h *Handler) GetTenantsByUserId(ctx *ginx.Context, req ListUserTenantsReq, sess session.Session) (ginx.Result, error) {
	// 获取租户ID
	tid := ctxutil.GetTenantID(ctx).Int64()

	// 获取该用户关联的租户列表（将当前租户 ID 注入，用于底层 SQL 隔离）
	tenants, total, err := h.svc.GetAttachedTenantsWithFilter(ctx.Context, req.UserID, tid, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrTenantList, err
	}

	return ginx.Result{
		Data: ListTenantRes{
			Total:   total,
			Tenants: ToTenantVOs(tenants),
		},
	}, nil
}
