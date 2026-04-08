package role

import (
	"github.com/Duke1616/eiam/internal/domain"
	permissionsvc "github.com/Duke1616/eiam/internal/service/permission"
	rolesvc "github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ekit/slice"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	capability.IRegistry
	svc     rolesvc.IRoleService
	permSvc permissionsvc.IPermissionService
}

func NewHandler(svc rolesvc.IRoleService, permSvc permissionsvc.IPermissionService) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("角色管理"),
		svc:       svc,
		permSvc:   permSvc,
	}
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/role")

	// 角色管理 (CRUD)
	g.POST("/create", h.Capability("创建角色", "iam:role:add").
		Dependency("cmdb:codebook:view").
		Handle(ginx.B[CreateRoleRequest](h.Create)),
	)
	g.POST("/update", h.Capability("修改角色", "iam:role:edit").
		Handle(ginx.B[UpdateRoleRequest](h.Update)),
	)
	g.POST("/list", h.Capability("角色列表查询", "iam:role:view").
		Handle(ginx.B[ListRoleRequest](h.List)),
	)
	g.GET("/detail/:code", h.Capability("角色详情查看", "iam:role:get").
		Handle(ginx.W(h.Detail)),
	)

	// 角色关系授权 (Relation)
	g.POST("/assign", h.Capability("角色分配操作", "iam:role:assign").
		Handle(ginx.BS[AssignRoleRequest](h.AssignRole)),
	)

	// 查询当前用户的角色 (供 User Context 使用)
	g.GET("/mine", h.Capability("查看个人角色", "iam:role:view_mine").
		Handle(ginx.BS[any](h.GetMyRoles)),
	)
}

func (h *Handler) Create(ctx *ginx.Context, req CreateRoleRequest) (ginx.Result, error) {
	id, err := h.svc.Create(ctx.Request.Context(), domain.Role{
		Name: req.Name,
		Code: req.Code,
		Desc: req.Desc,
	})
	if err != nil {
		return ErrRoleCreateFailed, err
	}
	return ginx.Result{Data: id}, nil
}

func (h *Handler) Update(ctx *ginx.Context, req UpdateRoleRequest) (ginx.Result, error) {
	_, err := h.svc.Update(ctx.Request.Context(), domain.Role{
		Name: req.Name,
		Code: req.Code,
		Desc: req.Desc,
	})
	if err != nil {
		return ErrRoleUpdateFailed, err
	}
	return ginx.Result{Msg: "更新成功"}, nil
}

func (h *Handler) List(ctx *ginx.Context, req ListRoleRequest) (ginx.Result, error) {
	roles, total, err := h.svc.List(ctx.Request.Context(), req.Offset, req.Limit)
	if err != nil {
		return ErrRoleListFailed, err
	}

	return ginx.Result{
		Data: RetrieveRole{
			Roles: slice.Map(roles, func(idx int, src domain.Role) Role {
				return h.toVo(src)
			}),
			Total: total,
		},
	}, nil
}

func (h *Handler) Detail(ctx *ginx.Context) (ginx.Result, error) {
	code, err := ctx.Param("code").String()
	if err != nil {
		return ErrRoleNotFound, err
	}
	r, err := h.svc.GetByCode(ctx.Request.Context(), code)
	if err != nil {
		return ErrRoleNotFound, err
	}
	return ginx.Result{Data: h.toVo(r)}, nil
}

func (h *Handler) AssignRole(ctx *ginx.Context, req AssignRoleRequest, sess session.Session) (ginx.Result, error) {
	ok, err := h.permSvc.AssignRoleToUser(ctx.Request.Context(), sess.Claims().Uid, req.RoleCode)
	if err != nil || !ok {
		return ErrRoleAssignFailed, err
	}
	return ginx.Result{Msg: "分配成功"}, nil
}

func (h *Handler) GetMyRoles(ctx *ginx.Context, req any, sess session.Session) (ginx.Result, error) {
	roles, err := h.permSvc.GetRolesForUser(ctx.Request.Context(), sess.Claims().Uid)
	if err != nil {
		return ErrGetMyRolesFailed, err
	}

	return ginx.Result{Data: roles}, nil
}

func (h *Handler) toVo(src domain.Role) Role {
	return Role{
		ID:   src.ID,
		Code: src.Code,
		Name: src.Name,
		Desc: src.Desc,
	}
}
