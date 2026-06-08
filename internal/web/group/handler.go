package group

import (
	"github.com/Duke1616/eiam/internal/domain"
	group_vc "github.com/Duke1616/eiam/internal/service/group"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ekit/slice"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	capability.IRegistry
	svc group_vc.IGroupService
}

func NewHandler(svc group_vc.IGroupService) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "group", "用户组管理"),
		svc:       svc,
	}
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/group")

	g.POST("/create", h.Capability("创建用户组", "add").
		Handle(ginx.B[CreateGroupRequest](h.Create)),
	)
	g.POST("/update", h.Capability("修改用户组", "edit").
		Handle(ginx.B[UpdateGroupRequest](h.Update)),
	)
	g.DELETE("/delete/:id", h.Capability("删除用户组", "delete").
		Handle(ginx.W(h.Delete)),
	)
	g.POST("/list", h.Capability("用户组列表", "view").
		Handle(ginx.B[ListGroupRequest](h.List)),
	)
	g.GET("/detail/:code", h.Capability("用户组详情", "get").
		Handle(ginx.W(h.Detail)),
	)
	g.POST("/members/assign", h.Capability("分配组成员", "assign_members").
		Handle(ginx.B[AssignMembersRequest](h.AssignMembers)),
	)
	g.POST("/members/remove", h.Capability("移除组成员", "remove_members").
		Handle(ginx.B[RemoveMembersRequest](h.RemoveMembers)),
	)
	g.POST("/members", h.Capability("组成员列表", "members").
		Handle(ginx.B[ListMembersRequest](h.ListMembers)),
	)
	g.POST("/role/assign", h.Capability("用户组分配角色", "assign_role").
		Handle(ginx.B[AssignRoleRequest](h.AssignRole)),
	)
	g.POST("/role/remove", h.Capability("用户组解绑角色", "remove_role").
		Handle(ginx.B[RemoveRoleRequest](h.RemoveRole)),
	)
	g.GET("/roles/:code", h.Capability("查看用户组角色", "roles").
		Handle(ginx.W(h.ListRoles)),
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

	res := slice.Map(groups, func(idx int, src domain.Group) Group {
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

	res := slice.Map(users, func(idx int, src domain.User) User {
		return h.toUserVo(src)
	})

	return ginx.Result{
		Data: ListMembersResponse{
			Total:   total,
			Members: res,
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

	roles, err := h.svc.ListRoles(ctx.Request.Context(), code)
	if err != nil {
		return ErrListGroupRolesFailed, err
	}

	return ginx.Result{Data: roles}, nil
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
