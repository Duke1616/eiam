package policy

import (
	"fmt"

	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	permSvc permission.IPermissionService
	sess    session.Provider
}

func NewHandler(permSvc permission.IPermissionService, sess session.Provider) *Handler {
	return &Handler{
		permSvc: permSvc,
		sess:    sess,
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/policy")
	// 鉴权接口本身需要公开，因为 SDK 内部会带上 Token 并在逻辑内自行校验
	g.POST("/check_login", ginx.W(h.CheckLogin))
	g.POST("/check_policy", ginx.B[CheckPolicyReq](h.CheckPolicy))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
}

// CheckLogin 实现 SDK 的登录状态校验
func (h *Handler) CheckLogin(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := h.sess.Get(&gctx.Context{Context: ctx.Context})
	if err != nil {
		return ginx.Result{Code: 401, Msg: "未登录"}, err
	}

	return ginx.Result{
		Code: 0,
		Data: map[string]int64{
			"uid": sess.Claims().Uid,
		},
	}, nil
}

// CheckPolicy 实现 SDK 的全链路权限判定决策
func (h *Handler) CheckPolicy(ctx *ginx.Context, req CheckPolicyReq) (ginx.Result, error) {
	// 1. 获取当前用户和租户上下文
	sess, err := h.sess.Get(&gctx.Context{Context: ctx.Context})
	if err != nil {
		return ginx.Result{Code: 401, Msg: "未登录"}, err
	}

	// 从 Context 提取租户 ID
	tid := ctxutil.GetTenantID(ctx.Context)

	// 2. 调用全链路 CheckAPI 逻辑 (物理 Path -> 能力码 -> 逻辑权限判定)
	allowed, err := h.permSvc.CheckAPI(ctx.Context, tid, sess.Claims().Uid, req.Service, req.Method, req.Path)
	if err != nil {
		return ginx.Result{
			Code: 0,
			Data: AuthorizeResult{
				Allowed: false,
				Reason:  fmt.Sprintf("鉴权逻辑校验出错: %v", err),
			},
		}, nil
	}

	// 3. 如果物理 API 校验通过，还需要针对具体的 Resource 维度进行逻辑判定 (OPA 处理)
	// 如果 req.Resource != "*"，我们需要额外加一道特定资源的 OPA 判定
	// 此处目前保留简化实现，物理 API 通过即通过

	return ginx.Result{
		Code: 0,
		Data: AuthorizeResult{
			Allowed: allowed,
		},
	}, nil
}

type CheckPolicyReq struct {
	Service  string `json:"service"`
	Path     string `json:"path"`
	Method   string `json:"method"`
	Resource string `json:"resource"`
}

type AuthorizeResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}
