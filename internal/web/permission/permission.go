package permission

import (
	permissionsvc "github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

const CodePrefix = "iam"

type Handler struct {
	capability.IRegistry
	svc permissionsvc.IPermissionService
}

func NewPermissionHandler(svc permissionsvc.IPermissionService) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("资源中心"),
		svc:       svc,
	}
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/permission")

	// 核心业务：查询当前用户的权限资产（用于前端渲染菜单）
	// NOTE: 装饰器 capability.Capability 与 handler 声明必须完全匹配以触发全链路资产发现
	g.GET("/menus", h.Capability("获取授权菜单", "iam:menu:view").
		Handle(ginx.W(h.GetAuthorizedMenus)),
	)
}

func (h *Handler) GetAuthorizedMenus(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ErrAuthMenuFailed, err
	}
	uid, err := sess.Get(ctx.Request.Context(), "uid").Int64()
	if err != nil {
		return ErrAuthMenuFailed, err
	}

	menus, err := h.svc.GetAuthorizedMenus(ctx.Request.Context(), uid)
	if err != nil {
		return ErrAuthMenuFailed, err
	}

	return ginx.Result{Data: menus}, nil
}
