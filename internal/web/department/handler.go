package department

import (
	"errors"

	"github.com/Duke1616/eiam/internal/domain"
	depts_vc "github.com/Duke1616/eiam/internal/service/department"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ekit/slice"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	capability.IRegistry
	svc depts_vc.IDepartmentService
}

func NewHandler(svc depts_vc.IDepartmentService) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "department", "部门管理"),
		svc:       svc,
	}
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/department")

	g.POST("/create", h.Capability("创建部门", "add").
		Handle(ginx.B[CreateDeptRequest](h.Create)),
	)
	g.POST("/update", h.Capability("修改部门", "edit").
		Handle(ginx.B[UpdateDeptRequest](h.Update)),
	)
	g.DELETE("/delete/:id", h.Capability("删除部门", "delete").
		Handle(ginx.W(h.Delete)),
	)
	g.GET("/list", h.Capability("部门树", "view").
		Handle(ginx.W(h.List)),
	)
	g.GET("/detail/:id", h.Capability("部门详情", "get").
		Handle(ginx.W(h.Detail)),
	)
	g.POST("/assign", h.Capability("分配部门成员", "assign").
		Handle(ginx.B[AssignUsersRequest](h.AssignUsers)),
	)
	g.POST("/remove", h.Capability("移除部门成员", "remove").
		Handle(ginx.B[RemoveUsersRequest](h.RemoveUsers)),
	)
	g.POST("/members", h.Capability("部门成员列表", "members").
		Handle(ginx.B[ListMembersRequest](h.ListMembers)),
	)
}

func (h *Handler) Create(ctx *ginx.Context, req CreateDeptRequest) (ginx.Result, error) {
	id, err := h.svc.Create(ctx.Request.Context(), domain.Department{
		ParentID:   req.ParentID,
		Name:       req.Name,
		Sort:       req.Sort,
		Leaders:    req.Leaders,
		MainLeader: req.MainLeader,
	})
	if err != nil {
		return ErrCreateDeptFailed, err
	}
	return ginx.Result{Data: id}, nil
}

func (h *Handler) Update(ctx *ginx.Context, req UpdateDeptRequest) (ginx.Result, error) {
	err := h.svc.Update(ctx.Request.Context(), domain.Department{
		ID:         req.ID,
		ParentID:   req.ParentID,
		Name:       req.Name,
		Sort:       req.Sort,
		Leaders:    req.Leaders,
		MainLeader: req.MainLeader,
	})
	if err != nil {
		return ErrUpdateDeptFailed, err
	}
	return ginx.Result{Msg: "更新部门成功"}, nil
}

func (h *Handler) Delete(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ginx.Result{Code: 400, Msg: "参数错误"}, err
	}

	err = h.svc.Delete(ctx.Request.Context(), id)
	if err != nil {
		if errors.Is(err, depts_vc.ErrDeleteDeptWithChildren) || errors.Is(err, depts_vc.ErrDeleteDeptWithMembers) {
			return ginx.Result{Code: 4010703, Msg: err.Error()}, nil
		}
		return ErrDeleteDeptFailed, err
	}
	return ginx.Result{Msg: "删除部门成功"}, nil
}

func (h *Handler) List(ctx *ginx.Context) (ginx.Result, error) {
	tree, err := h.svc.List(ctx.Request.Context())
	if err != nil {
		return ErrListDeptFailed, err
	}

	res := slice.Map(tree, func(idx int, src *domain.DepartmentNode) *DepartmentNode {
		return h.toNodeVo(src)
	})

	return ginx.Result{Data: res}, nil
}

func (h *Handler) Detail(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ginx.Result{Code: 400, Msg: "参数错误"}, err
	}

	dept, err := h.svc.GetByID(ctx.Request.Context(), id)
	if err != nil {
		return ErrGetDeptDetailFailed, err
	}

	return ginx.Result{
		Data: Department{
			ID:         dept.ID,
			ParentID:   dept.ParentID,
			Name:       dept.Name,
			Sort:       dept.Sort,
			Leaders:    dept.Leaders,
			MainLeader: dept.MainLeader,
			Ctime:      dept.Ctime,
			Utime:      dept.Utime,
		},
	}, nil
}

func (h *Handler) AssignUsers(ctx *ginx.Context, req AssignUsersRequest) (ginx.Result, error) {
	err := h.svc.AssignUsers(ctx.Request.Context(), req.DeptID, req.UserIDs)
	if err != nil {
		return ErrAssignUsersFailed, err
	}
	return ginx.Result{Msg: "分配部门成员成功"}, nil
}

func (h *Handler) RemoveUsers(ctx *ginx.Context, req RemoveUsersRequest) (ginx.Result, error) {
	err := h.svc.RemoveUsers(ctx.Request.Context(), req.DeptID, req.UserIDs)
	if err != nil {
		return ErrRemoveUsersFailed, err
	}
	return ginx.Result{Msg: "移出部门成员成功"}, nil
}

func (h *Handler) ListMembers(ctx *ginx.Context, req ListMembersRequest) (ginx.Result, error) {
	users, total, err := h.svc.ListMembers(ctx.Request.Context(), req.DeptID, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrListDeptMembersFailed, err
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

func (h *Handler) toNodeVo(node *domain.DepartmentNode) *DepartmentNode {
	if node == nil {
		return nil
	}

	children := make([]*DepartmentNode, 0, len(node.Children))
	for _, child := range node.Children {
		children = append(children, h.toNodeVo(child))
	}

	return &DepartmentNode{
		Department: Department{
			ID:         node.ID,
			ParentID:   node.ParentID,
			Name:       node.Name,
			Sort:       node.Sort,
			Leaders:    node.Leaders,
			MainLeader: node.MainLeader,
			Ctime:      node.Ctime,
			Utime:      node.Utime,
		},
		Children: children,
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
