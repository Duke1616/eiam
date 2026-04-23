package role

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	permissionsvc "github.com/Duke1616/eiam/internal/service/permission"
	rolesvc "github.com/Duke1616/eiam/internal/service/role"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
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
	userSvc usersvc.IUserService
}

func NewHandler(svc rolesvc.IRoleService, permSvc permissionsvc.IPermissionService, userSvc usersvc.IUserService) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "role", "角色管理"),
		svc:       svc,
		permSvc:   permSvc,
		userSvc:   userSvc,
	}
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/role")

	// 角色管理 (CRUD)
	g.POST("/create", h.Capability("创建角色", "add").
		Needs("cmdb:codebook:view").
		Handle(ginx.B[CreateRoleRequest](h.Create)),
	)
	g.POST("/update", h.Capability("修改角色", "edit").
		Handle(ginx.B[UpdateRoleRequest](h.Update)),
	)
	g.POST("/list", h.Capability("角色列表", "view").
		Handle(ginx.B[ListRoleRequest](h.List)),
	)
	g.GET("/detail/:code", h.Capability("角色详情", "get").
		Handle(ginx.W(h.Detail)),
	)
	g.DELETE("/delete/:id", h.Capability("删除角色", "delete").
		Handle(ginx.W(h.Delete)),
	)

	// 角色关系授权 (Relation)
	g.POST("/assign", h.Capability("角色分配", "assign").
		Handle(ginx.BS[AssignRoleRequest](h.AssignRole)),
	)

	g.POST("/batch_assign", h.Capability("批量分配角色", "batch_assign").
		Handle(ginx.B[BatchAssignRoleRequest](h.BatchAssignRole)),
	)

	g.POST("/analysis/inline", h.Capability("分析内联策略", "analysis").
		Handle(ginx.B[RoleAnalysisReq](h.AnalyzeInlinePolicies)),
	)
	g.POST("/add_parent", h.Capability("添加父角色", "add_parent").
		Handle(ginx.B[RoleInheritanceReq](h.AddParentRole)),
	)
	g.POST("/remove_parent", h.Capability("移除父角色", "remove_parent").
		Handle(ginx.B[RoleInheritanceReq](h.RemoveParentRole)),
	)
	g.POST("/parents", h.Capability("获取父角色", "view_parents").
		Handle(ginx.B[GetParentRolesReq](h.GetParentRoles)),
	)

	// 查询当前用户的角色 (供 User Context 使用)
	g.GET("/mine", h.Capability("查看个人角色", "view_mine").
		Handle(ginx.BS[any](h.GetMyRoles)),
	)

	// 查询特定用户的关联角色 (管理侧使用)
	g.POST("/list/attached/user", h.Capability("查询用户角色", "view_user_roles").
		Handle(ginx.B[ListUserRolesRequest](h.GetRolesByUserId)),
	)
}

func (h *Handler) GetRolesByUserId(ctx *ginx.Context, req ListUserRolesRequest) (ginx.Result, error) {
	id := req.UserID
	if id == 0 {
		return ErrInvalidUserId, nil
	}

	// 设置默认分页
	if req.Limit <= 0 {
		req.Limit = 10
	}

	// 1. 获取用户信息，拿到 username
	u, err := h.userSvc.GetById(ctx.Request.Context(), id)
	if err != nil {
		return ErrGetUserFailed, err
	}

	// 2. 获取用户直接关联的角色 (支持数据库分页与关键词过滤)
	roles, total, err := h.svc.ListAttachedRoles(ctx.Request.Context(), u.Username, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrGetUserRoleCodeFailed, err
	}

	// 5. 映射为 VO 并按 RetrieveRole 格式返回
	return ginx.Result{
		Data: RetrieveRole{
			Total: total,
			Roles: slice.Map(roles, func(idx int, src domain.Role) Role {
				return h.toVo(src)
			}),
		},
	}, nil
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
		ID:   req.ID,
		Name: req.Name,
		Code: req.Code,
		Desc: req.Desc,
	})
	if err != nil {
		return ErrRoleUpdateFailed, err
	}
	return ginx.Result{Msg: "更新成功"}, nil
}

func (h *Handler) Delete(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrRoleDeleteFailed, err
	}

	err = h.svc.Delete(ctx.Request.Context(), id)
	if err != nil {
		return ErrRoleDeleteFailed, err
	}

	return ginx.Result{Msg: "删除角色成功"}, nil
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

func (h *Handler) AnalyzeInlinePolicies(ctx *ginx.Context, req RoleAnalysisReq) (ginx.Result, error) {
	// 1. 获取角色及其内联策略
	r, err := h.svc.GetByCode(ctx.Request.Context(), req.RoleCode)
	if err != nil {
		return ErrRoleNotFound, err
	}

	// 2. 批量计算内联策略的摘要分析
	vo := h.toVo(r)
	summaries, err := h.permSvc.GetPoliciesSummary(ctx.Request.Context(), r.InlinePolicies)
	if err != nil {
		return ErrGetRoleAnalysisFailed, err
	}

	for i, s := range summaries {
		vo.InlinePolicies[i].Services = h.toServiceSummaryVOs(s.Services)
	}

	return ginx.Result{
		Data: RoleAnalysisRes{
			InlinePolicies: vo.InlinePolicies,
		},
	}, nil
}

func (h *Handler) AddParentRole(ctx *ginx.Context, req RoleInheritanceReq) (ginx.Result, error) {
	_, err := h.permSvc.AddRoleInheritance(ctx.Request.Context(), req.RoleCode, req.ParentRoleCode)
	if err != nil {
		return ginx.Result{Code: 50101, Msg: "添加父角色失败"}, err
	}
	return ginx.Result{Msg: "添加成功"}, nil
}

func (h *Handler) RemoveParentRole(ctx *ginx.Context, req RoleInheritanceReq) (ginx.Result, error) {
	_, err := h.permSvc.RemoveRoleInheritance(ctx.Request.Context(), req.RoleCode, req.ParentRoleCode)
	if err != nil {
		if errors.Is(err, errs.ErrImmutableInheritance) {
			return ErrImmutableInheritance, err
		}
		return ginx.Result{Code: 50102, Msg: "移除父角色失败"}, err
	}
	return ginx.Result{Msg: "移除成功"}, nil
}

func (h *Handler) GetParentRoles(ctx *ginx.Context, req GetParentRolesReq) (ginx.Result, error) {
	infos, err := h.permSvc.GetParentRoles(ctx.Request.Context(), req.RoleCode)
	if err != nil {
		return ginx.Result{Code: 50103, Msg: "获取父角色失败"}, err
	}

	return ginx.Result{
		Data: slice.Map(infos, func(idx int, src domain.InheritanceInfo) RoleInheritanceInfo {
			return RoleInheritanceInfo{
				Code:        src.Code,
				IsDirect:    src.IsDirect,
				IsImmutable: src.IsImmutable,
			}
		}),
	}, nil
}

func (h *Handler) AssignRole(ctx *ginx.Context, req AssignRoleRequest, sess session.Session) (ginx.Result, error) { // 1. 获取当前用户和租户上下文
	username, ok := sess.Claims().Data["username"]
	if !ok {
		return ErrUnauthenticated, fmt.Errorf("session 中缺失用户名信息")
	}

	_, err := h.permSvc.AssignRoleToUser(ctx.Request.Context(), username, req.RoleCode)
	if err != nil {
		return ErrRoleAssignFailed, err
	}
	return ginx.Result{Msg: "分配成功"}, nil
}

func (h *Handler) BatchAssignRole(ctx *ginx.Context, req BatchAssignRoleRequest) (ginx.Result, error) {
	_, err := h.permSvc.AssignUsersToRole(ctx.Request.Context(), req.RoleCode, req.Usernames)
	if err != nil {
		return ErrRoleAssignFailed, err
	}
	return ginx.Result{Msg: "批量分配成功"}, nil
}

func (h *Handler) GetMyRoles(ctx *ginx.Context, req any, sess session.Session) (ginx.Result, error) {
	username, ok := sess.Claims().Data["username"]
	if !ok {
		return ErrUnauthenticated, fmt.Errorf("session 中缺失用户名信息")
	}

	roles, err := h.permSvc.GetRolesForUser(ctx.Request.Context(), username)
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
		Type: src.Type,
		InlinePolicies: slice.Map(src.InlinePolicies, func(idx int, src domain.Policy) Policy {
			return h.toPolicyVO(src)
		}),
		Ctime: src.Ctime,
		Utime: src.Utime,
	}
}

func (h *Handler) toPolicyVO(p domain.Policy) Policy {
	return Policy{
		Name: p.Name,
		Code: p.Code,
		Statement: slice.Map(p.Statement, func(idx int, s domain.Statement) Statement {
			return Statement{
				Effect:   string(s.Effect),
				Action:   s.Action,
				Resource: s.Resource,
				Condition: slice.Map(s.Condition, func(idx int, c domain.Condition) Condition {
					return Condition{
						Operator: c.Operator,
						Key:      c.Key,
						Value:    c.Value,
					}
				}),
			}
		}),
	}
}

func (h *Handler) toServiceSummaryVOs(summaries []domain.PolicyServiceSummary) []ServiceSummary {
	return slice.Map(summaries, func(idx int, src domain.PolicyServiceSummary) ServiceSummary {
		return ServiceSummary{
			ServiceCode:   src.ServiceCode,
			ServiceName:   src.ServiceName,
			Effect:        string(src.Effect),
			Level:         string(src.Level),
			GrantedCount:  src.GrantedCount,
			TotalCount:    src.TotalCount,
			ResourceScope: src.ResourceScope,
			Condition: func() string {
				if len(src.Conditions) == 0 {
					return "-"
				}
				b, _ := json.Marshal(src.Conditions)
				return string(b)
			}(),
			Actions: slice.Map(src.Actions, func(idx int, pct domain.GrantedAction) ActionDetail {
				// 格式化资源
				resStr := strings.Join(pct.Resource, ", ")

				// 格式化条件
				condStr := "-"
				if len(pct.Condition) > 0 {
					b, _ := json.Marshal(pct.Condition)
					condStr = string(b)
				}

				return ActionDetail{
					Code:      pct.Code,
					Name:      pct.Name,
					Group:     pct.Group,
					Resource:  resStr,
					Condition: condStr,
				}
			}),
		}
	})
}
