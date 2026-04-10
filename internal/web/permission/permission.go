package permission

import (
	permissionsvc "github.com/Duke1616/eiam/internal/service/permission"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc permissionsvc.IPermissionService
}

func NewHandler(svc permissionsvc.IPermissionService) *Handler {
	return &Handler{
		svc: svc,
	}
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/permission")

	// 核心业务：查询当前用户的权限资产（用于前端渲染菜单）
	g.GET("/menus", ginx.W(h.GetAuthorizedMenus))
}

func (h *Handler) GetAuthorizedMenus(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ErrAuthMenuFailed, err
	}

	menus, err := h.svc.GetAuthorizedMenus(ctx.Request.Context(), sess.Claims().Uid)
	if err != nil {
		return ErrAuthMenuFailed, err
	}

	return ginx.Result{Data: menus}, nil
}
