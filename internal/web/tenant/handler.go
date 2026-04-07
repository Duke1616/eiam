package tenant

import (
	"strconv"

	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc  tenant.ITenantService
	sess session.Provider
}

func NewHandler(svc tenant.ITenantService, sess session.Provider) *Handler {
	return &Handler{
		svc:  svc,
		sess: sess,
	}
}

func (h *Handler) ProvidePermissions() []capability.Permission {
	return []capability.Permission{
		{Code: "iam:tenant:create", Name: "创建租户空间", Group: "租户管理", Desc: "允许用户初始化并拥有一个全新的租户空间"},
		{Code: "iam:tenant:list", Name: "获取所属租户", Group: "租户管理", Desc: "允许获取当前用户关联的所有租户清单"},
		{Code: "iam:tenant:switch", Name: "切换租户上下文", Group: "租户管理", Desc: "允许在不同租户空间之间动态切换并重新鉴权"},
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/tenant")
	// 租户空间创建
	g.POST("/create", capability.Capability("创建工作空间", "iam:tenant:create")(
		ginx.B[CreateTenantReq](h.CreateTenant)),
	)
	// 获取我所属的所有租户列表 (用于下拉框展示)
	g.GET("/list_mine", capability.Capability("检索我所属的租户", "iam:tenant:list")(
		ginx.W(h.ListMyTenants)),
	)
	// 【核心：租户上下文切换】
	g.POST("/switch", capability.Capability("动态切换租户上下文", "iam:tenant:switch")(
		ginx.B[SwitchTenantReq](h.SwitchTenant)),
	)
}

// CreateTenant 允许用户主动创建一个属于自己的企业/工作空间
func (h *Handler) CreateTenant(ctx *ginx.Context, req CreateTenantReq) (ginx.Result, error) {
	sess, err := h.sess.Get(&gctx.Context{Context: ctx.Context})
	if err != nil {
		return ErrUnauthorized, err
	}

	uid := sess.Claims().Uid
	tenantId, err := h.svc.CreateTenant(ctx.Request.Context(), req.Name, req.Code, uid)
	if err != nil {
		return ErrTenantCreate, err
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
