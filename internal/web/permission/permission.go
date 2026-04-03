package permission

import (
	"github.com/Duke1616/eiam/internal/domain"
	permissionsvc "github.com/Duke1616/eiam/internal/service/permission"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc permissionsvc.IPermissionService
}

func NewPermissionHandler(svc permissionsvc.IPermissionService) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/permission")
	g.POST("/create", ginx.B[CreatePermissionRequest](h.CreatePermission))
	g.POST("/bind", ginx.B[BindResourcesRequest](h.BindResources))
	g.POST("/role/assign", ginx.B[AssignRoleRequest](h.AssignRole))
	g.GET("/menus", ginx.W(h.GetAuthorizedMenus))
	g.GET("/roles", ginx.W(h.GetRolesForUser))
}

func (h *Handler) CreatePermission(ctx *ginx.Context, req CreatePermissionRequest) (ginx.Result, error) {
	id, err := h.svc.CreatePermission(ctx.Request.Context(), domain.Permission{
		Code: req.Code,
		Desc: req.Desc,
	})
	if err != nil {
		return ErrPermissionCreateFailed, err
	}
	return ginx.Result{Data: id}, nil
}

func (h *Handler) BindResources(ctx *ginx.Context, req BindResourcesRequest) (ginx.Result, error) {
	err := h.svc.BindResourcesToPermission(ctx.Request.Context(), req.PermID, req.PermCode, req.ResType, req.ResIDs)
	if err != nil {
		return ErrBindFailed, err
	}
	return ginx.Result{Msg: "绑定成功"}, nil
}

func (h *Handler) AssignRole(ctx *ginx.Context, req AssignRoleRequest) (ginx.Result, error) {
	ok, err := h.svc.AssignRoleToUser(ctx.Request.Context(), req.UserID, req.RoleCode)
	if err != nil || !ok {
		return ErrAssignRoleFailed, err
	}
	
	return ginx.Result{Msg: "分配角色成功"}, nil
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

func (h *Handler) GetRolesForUser(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ErrAuthMenuFailed, err
	}
	uid, err := sess.Get(ctx.Request.Context(), "uid").Int64()
	if err != nil {
		return ErrAuthMenuFailed, err
	}

	roles, err := h.svc.GetRolesForUser(ctx.Request.Context(), uid)
	if err != nil {
		return ErrAuthMenuFailed, err
	}

	return ginx.Result{Data: roles}, nil
}
