package group

import (
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/service/group"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/pkg/contract/model"
	"github.com/Duke1616/eiam/pkg/contract/permission"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

type Handler struct {
	capability.IRegistry
	svc     group.IGroupService
	roleSvc role.IRoleService
}

func NewHandler(svc group.IGroupService, roleSvc role.IRoleService) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "group", "用户分组"),
		svc:       svc,
		roleSvc:   roleSvc,
	}
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/group")

	g.POST("/create", h.Define("创建用户组", "add").
		Bind(ginx.B[CreateGroupRequest](h.Create)),
	)
	g.POST("/update", h.Define("修改用户组", "edit").
		Needs(permission.Group.Get).
		Bind(ginx.B[UpdateGroupRequest](h.Update)),
	)
	g.DELETE("/delete/:id", h.Define("删除用户组", "delete").
		Bind(ginx.W(h.Delete)),
	)
	g.POST("/list", h.Define("用户组列表", "view").
		Bind(ginx.B[ListGroupRequest](h.List)),
	)
	g.GET("/detail/:code", h.Define("用户组详情", "get").
		Bind(ginx.W(h.Detail)),
	)
	g.POST("/members/assign", h.Define("分配组成员", "assign_members").
		Needs(permission.User.View, permission.Group.View).
		Bind(ginx.B[AssignMembersRequest](h.AssignMembers)),
	)
	g.POST("/members/remove", h.Define("移除组成员", "remove_members").
		Bind(ginx.B[RemoveMembersRequest](h.RemoveMembers)),
	)
	g.POST("/members", h.Define("组成员列表", "members").
		Bind(ginx.B[ListMembersRequest](h.ListMembers)),
	)
	g.POST("/list/attached/user", h.For(model.User).Define("查询用户所属分组", "view_user_groups").
		Bind(ginx.B[ListAttachedUserGroupsRequest](h.ListAttachedUserGroups)),
	)
	g.POST("/list/attached/role", h.For(model.Role).Define("查询角色关联分组", "view_role_groups").
		Bind(ginx.B[ListAttachedRoleGroupsRequest](h.ListAttachedRoleGroups)),
	)
	g.POST("/role/assign", h.Define("用户组分配角色", "assign_role").
		Needs(permission.Role.View, permission.Group.View).
		Bind(ginx.B[AssignRoleRequest](h.AssignRole)),
	)
	g.POST("/role/remove", h.Define("用户组解绑角色", "remove_role").
		Bind(ginx.B[RemoveRoleRequest](h.RemoveRole)),
	)
	g.GET("/roles/:code", h.Define("查看用户组角色", "roles").
		Bind(ginx.W(h.ListRoles)),
	)
}

func (h *Handler) Create(ctx *ginx.Context, req CreateGroupRequest) (ginx.Result, error) {
	id, err := h.svc.Create(ctx.Request.Context(), domain.Group{
		Name: req.Name,
		Code: req.Code,
		Desc: req.Desc,
	})
	if err != nil {
		return ErrCreateGroupFailed, err
	}
	return ginx.Result{Data: id}, nil
}

func (h *Handler) Update(ctx *ginx.Context, req UpdateGroupRequest) (ginx.Result, error) {
	err := h.svc.Update(ctx.Request.Context(), domain.Group{
		ID:   req.ID,
		Name: req.Name,
		Desc: req.Desc,
	})
	if err != nil {
		return ErrUpdateGroupFailed, err
	}
	return ginx.Result{Msg: "更新用户组信息成功"}, nil
}

func (h *Handler) Delete(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ginx.Result{Code: 400, Msg: "参数错误"}, err
	}

	err = h.svc.Delete(ctx.Request.Context(), id)
	if err != nil {
		return ErrDeleteGroupFailed, err
	}
	return ginx.Result{Msg: "删除用户组成功"}, nil
}

func (h *Handler) List(ctx *ginx.Context, req ListGroupRequest) (ginx.Result, error) {
	groups, total, err := h.svc.List(ctx.Request.Context(), req.Offset, req.Limit)
	if err != nil {
		return ErrListGroupFailed, err
	}

	res := lo.Map(groups, func(src domain.Group, _ int) Group {
		return h.toGroupVo(src)
	})

	return ginx.Result{
		Data: ListGroupsResponse{
			Total:  total,
			Groups: res,
		},
	}, nil
}

func (h *Handler) Detail(ctx *ginx.Context) (ginx.Result, error) {
	code, err := ctx.Param("code").String()
	if err != nil {
		return ginx.Result{Code: 400, Msg: "参数错误"}, err
	}
	if code == "" {
		return ginx.Result{Code: 400, Msg: "参数错误"}, nil
	}

	group, err := h.svc.GetByCode(ctx.Request.Context(), code)
	if err != nil {
		return ErrGetGroupDetailFailed, err
	}

	return ginx.Result{
		Data: h.toGroupVo(group),
	}, nil
}

func (h *Handler) AssignMembers(ctx *ginx.Context, req AssignMembersRequest) (ginx.Result, error) {
	_, err := h.svc.AssignMembers(ctx.Request.Context(), req.GroupCode, req.Usernames)
	if err != nil {
		return ErrAssignMembersFailed, err
	}
	return ginx.Result{Msg: "分配组成员成功"}, nil
}

func (h *Handler) RemoveMembers(ctx *ginx.Context, req RemoveMembersRequest) (ginx.Result, error) {
	_, err := h.svc.RemoveMembers(ctx.Request.Context(), req.GroupCode, req.Usernames)
	if err != nil {
		return ErrRemoveMembersFailed, err
	}
	return ginx.Result{Msg: "移出组成员成功"}, nil
}

func (h *Handler) ListMembers(ctx *ginx.Context, req ListMembersRequest) (ginx.Result, error) {
	users, total, err := h.svc.ListMembers(ctx.Request.Context(), req.GroupCode, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrListGroupMembersFailed, err
	}

	res := lo.Map(users, func(src domain.User, _ int) User {
		return h.toUserVo(src)
	})

	return ginx.Result{
		Data: ListMembersResponse{
			Total:   total,
			Members: res,
		},
	}, nil
}

func (h *Handler) ListAttachedUserGroups(ctx *ginx.Context, req ListAttachedUserGroupsRequest) (ginx.Result, error) {
	groups, total, err := h.svc.ListAttachedGroupsByUser(ctx.Request.Context(), req.Username, req.UserID, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrListAttachedGroupsFailed, err
	}

	res := lo.Map(groups, func(src domain.Group, _ int) Group {
		return h.toGroupVo(src)
	})

	return ginx.Result{
		Data: ListGroupsResponse{
			Total:  total,
			Groups: res,
		},
	}, nil
}

func (h *Handler) ListAttachedRoleGroups(ctx *ginx.Context, req ListAttachedRoleGroupsRequest) (ginx.Result, error) {
	groups, total, err := h.svc.ListAttachedGroupsByRole(ctx.Request.Context(), req.RoleCode, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrListAttachedGroupsFailed, err
	}

	res := lo.Map(groups, func(src domain.Group, _ int) Group {
		return h.toGroupVo(src)
	})

	return ginx.Result{
		Data: ListGroupsResponse{
			Total:  total,
			Groups: res,
		},
	}, nil
}

func (h *Handler) AssignRole(ctx *ginx.Context, req AssignRoleRequest) (ginx.Result, error) {
	_, err := h.svc.AssignRole(ctx.Request.Context(), req.GroupCode, req.RoleCode)
	if err != nil {
		return ErrAssignGroupRoleFailed, err
	}
	return ginx.Result{Msg: "授权角色成功"}, nil
}

func (h *Handler) RemoveRole(ctx *ginx.Context, req RemoveRoleRequest) (ginx.Result, error) {
	_, err := h.svc.RemoveRole(ctx.Request.Context(), req.GroupCode, req.RoleCode)
	if err != nil {
		return ErrRemoveGroupRoleFailed, err
	}
	return ginx.Result{Msg: "解绑角色成功"}, nil
}

func (h *Handler) ListRoles(ctx *ginx.Context) (ginx.Result, error) {
	code, err := ctx.Param("code").String()
	if err != nil {
		return ginx.Result{Code: 400, Msg: "参数错误"}, err
	}
	if code == "" {
		return ginx.Result{Code: 400, Msg: "参数错误"}, nil
	}

	roleCodes, err := h.svc.ListRoles(ctx.Request.Context(), code)
	if err != nil {
		return ErrListGroupRolesFailed, err
	}

	if len(roleCodes) == 0 {
		return ginx.Result{Data: []Role{}}, nil
	}

	roles, err := h.roleSvc.ListByIncludeCodes(ctx.Request.Context(), roleCodes)
	if err != nil {
		return ErrListGroupRolesFailed, err
	}

	return ginx.Result{
		Data: lo.Map(roles, func(src domain.Role, _ int) Role {
			return h.toRoleVo(src)
		}),
	}, nil
}

func (h *Handler) toGroupVo(g domain.Group) Group {
	return Group{
		ID:    g.ID,
		Name:  g.Name,
		Code:  g.Code,
		Desc:  g.Desc,
		Ctime: g.Ctime,
		Utime: g.Utime,
	}
}

func (h *Handler) toRoleVo(r domain.Role) Role {
	return Role{
		ID:    r.ID,
		Code:  r.Code,
		Name:  r.Name,
		Desc:  r.Desc,
		Ctime: r.Ctime,
		Utime: r.Utime,
	}
}

func (h *Handler) toUserVo(u domain.User) User {
	return User{
		ID:       u.ID,
		Username: u.Username,
		Nickname: u.Profile.Nickname,
		Avatar:   u.Profile.Avatar,
		Email:    u.Email,
		Phone:    u.Profile.Phone,
	}
}
