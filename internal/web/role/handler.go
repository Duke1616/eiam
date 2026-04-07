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
	svc     rolesvc.IRoleService
	permSvc permissionsvc.IPermissionService
}

func NewHandler(svc rolesvc.IRoleService, permSvc permissionsvc.IPermissionService) *Handler {
	return &Handler{
		svc:     svc,
		permSvc: permSvc,
	}
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/role")

	// 角色管理 (CRUD)
	g.POST("/create", capability.Capability("创建角色", "iam:role:create")(
		ginx.B[CreateRoleRequest](h.Create)),
	)
	g.POST("/update", capability.Capability("修改角色", "iam:role:update")(
		ginx.B[UpdateRoleRequest](h.Update)),
	)
	g.POST("/list", capability.Capability("角色列表查询", "iam:role:list")(
		ginx.B[ListRoleRequest](h.List)),
	)
	g.GET("/detail/:code", capability.Capability("角色详情查看", "iam:role:view")(
		ginx.W(h.Detail)),
	)

	// 角色关系授权 (Relation)
	g.POST("/assign", capability.Capability("角色分配操作", "iam:role:assign")(
		ginx.BS[AssignRoleRequest](h.AssignRole)),
	)

	// 查询当前用户的角色 (供 User Context 使用)
	g.GET("/mine", capability.Capability("查看个人角色", "iam:role:view_mine")(
		ginx.BS[any](h.GetMyRoles)),
	)
}

func (h *Handler) ProvidePermissions() []capability.Permission {
	return []capability.Permission{
		{Code: "iam:role:create", Name: "创建角色能力", Group: "角色管理", Desc: "允许在系统中录入新角色"},
		{Code: "iam:role:update", Name: "修改角色能力", Group: "角色管理", Desc: "允许修改角色元数据及权限策略"},
		{Code: "iam:role:list", Name: "角色列表查询能力", Group: "角色管理", Desc: "允许查看系统角色清单"},
		{Code: "iam:role:view", Name: "角色详情查看能力", Group: "角色管理", Desc: "允许查看角色具体权限配置"},
		{Code: "iam:role:assign", Name: "角色分配权限", Group: "角色管理", Desc: "允许将角色授予指定用户"},
		{Code: "iam:role:view_mine", Name: "查看自我角色", Group: "基础能力", Desc: "允许用户查看自己拥有的角色列表"},
	}
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
