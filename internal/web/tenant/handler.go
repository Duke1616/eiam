package tenant

import (
	"strconv"

	"github.com/Duke1616/eiam/internal/service/tenant"
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

func (h *Handler) PublicRoutes(server *gin.Engine) {
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/tenant")
	// 获取我所属的所有租户列表 (用于下拉框展示)
	g.POST("/list_mine", ginx.W(h.ListMyTenants))
	// 【核心：租户上下文切换】
	g.POST("/switch", ginx.B[SwitchTenantReq](h.SwitchTenant))
}

// ListMyTenants 获取当前登录用户可操作的所有租户列表
func (h *Handler) ListMyTenants(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := h.sess.Get(&gctx.Context{Context: ctx.Context})
	if err != nil {
		return ginx.Result{Code: 401, Msg: "未登录"}, err
	}

	// 从服务层获取该用户的所有租户映射
	tenants, err := h.svc.GetTenantsByUserId(ctx.Context, sess.Claims().Uid)
	if err != nil {
		return ginx.Result{Code: 500, Msg: "获取所属租户失败"}, err
	}

	return ginx.Result{
		Code: 0,
		Data: tenants,
	}, nil
}

// SwitchTenant 实现“租户上下文动态录入”
func (h *Handler) SwitchTenant(ctx *ginx.Context, req SwitchTenantReq) (ginx.Result, error) {
	sess, err := h.sess.Get(&gctx.Context{Context: ctx.Context})
	if err != nil {
		return ginx.Result{Code: 401, Msg: "未登录"}, err
	}

	// 1. 安全校验：确认该用户是否真的属于目标租户
	// NOTE: 在大型系统中，这里会调用 Casbin.GetRolesForUserInDomain 确认
	hasAccess, err := h.svc.CheckUserTenantAccess(ctx.Context, sess.Claims().Uid, req.TenantID)
	if err != nil || !hasAccess {
		return ginx.Result{Code: 403, Msg: "您无权切换至该租户空间"}, nil
	}

	// 2. 【核心录入点】：重新构建 Session 并注入新的租户 ID
	jwtData := map[string]string{
		"tenant_id": strconv.FormatInt(req.TenantID, 10),
	}

	// 重新 Build Session (Renew Token with new identity)
	_, err = session.NewSessionBuilder(&gctx.Context{Context: ctx.Context}, sess.Claims().Uid).
		SetJwtData(jwtData).
		Build()

	if err != nil {
		return ginx.Result{Code: 500, Msg: "租户上下文切换失败"}, err
	}

	return ginx.Result{
		Code: 0,
		Msg:  "成功切换至新租户空间",
	}, nil
}

type SwitchTenantReq struct {
	TenantID int64 `json:"tenant_id"`
}
