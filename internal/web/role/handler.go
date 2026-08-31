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
	"github.com/Duke1616/eiam/pkg/contract/model"
	"github.com/Duke1616/eiam/pkg/contract/permission"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
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
	g.POST("/create", h.Define("创建角色", "add").
		Bind(ginx.B[CreateRoleRequest](h.Create)),
	)
	g.POST("/update", h.Define("修改角色", "edit").
		Needs(permission.Role.Get).
		Bind(ginx.B[UpdateRoleRequest](h.Update)),
	)

	// 角色列表与详情属于不同细粒度权限
	g.POST("/list", h.Define("角色列表", "view").
		Bind(ginx.B[ListRoleRequest](h.List)),
	)
	g.GET("/detail/:code", h.Define("角色详情", "get").
		Bind(ginx.W(h.Detail)),
	)

	g.DELETE("/delete/:id", h.Define("删除角色", "delete").
		Bind(ginx.W(h.Delete)),
	)
	g.POST("/batch_delete", h.Define("批量删除角色", "batch_delete").
		Bind(ginx.B[BatchDeleteReq](h.BatchDelete)),
	)

	// 角色关系授权 (Relation)
	g.POST("/batch_assign", h.Define("批量分配角色", "batch_assign").
		Needs(permission.Role.View, permission.User.View).
		Bind(ginx.B[BatchAssignRoleRequest](h.BatchAssignRole)),
	)
	g.POST("/batch_unassign", h.Define("批量移除角色", "batch_unassign").
		Bind(ginx.B[BatchUnassignRoleRequest](h.BatchUnassignRole)),
	)
	g.POST("/unassign", h.Define("移除角色分配", "unassign").
		Bind(ginx.B[UnassignRoleRequest](h.UnassignRole)),
	)

	g.POST("/analysis/inline", h.Define("分析内联策略", "analysis").
		Bind(ginx.B[RoleAnalysisReq](h.AnalyzeInlinePolicies)),
	)
	g.POST("/add_parent", h.Define("添加父角色", "add_parent").
		Needs(permission.Role.View).
		Bind(ginx.B[RoleInheritanceReq](h.AddParentRole)),
	)
	g.POST("/remove_parent", h.Define("移除父角色", "remove_parent").
		Bind(ginx.B[RoleInheritanceReq](h.RemoveParentRole)),
	)
	g.POST("/parents", h.Define("获取父角色", "view_parents").
		Bind(ginx.B[GetParentRolesReq](h.GetParentRoles)),
	)

	// 查询当前用户的角色 (供 User Context 使用)
	g.GET("/mine", h.Define("查看个人角色", "view_mine").
		Bind(ginx.BS[any](h.GetMyRoles)),
	)

	// 跨领域：查询特定用户的关联角色 (直接使用纯契约 model.User)
	g.POST("/list/attached/user", h.For(model.User).Define("查询用户角色", "view_user_roles").
		Bind(ginx.B[ListUserRolesRequest](h.GetRolesByUserId)),
	)
}

func (h *Handler) GetRolesByUserId(ctx *ginx.Context, req ListUserRolesRequest) (ginx.Result, error) {
	id := req.UserID
	if id == 0 {
		return ErrInvalidUserId, nil
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
			Roles: lo.Map(roles, func(src domain.Role, _ int) Role {
				return h.toVo(src)
			}),
		},
	}, nil
}

func (h *Handler) Create(ctx *ginx.Context, req CreateRoleRequest) (ginx.Result, error) {
	// 拦截系统保留标识码，提供友好提示
	if req.Code == "super_admin" || req.Code == "admin" {
		return ErrReservedRoleCode, nil
	}

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
	// 拦截系统保留标识码的修改
	if req.Code == "super_admin" || req.Code == "admin" {
		return ErrReservedRoleCode, nil
	}

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

	if err = h.svc.Delete(ctx.Request.Context(), id); err != nil {
		if errors.Is(err, errs.ErrDeleteSystemRole) {
			return ErrReservedRoleCode, err
		}
		if errors.Is(err, errs.ErrRoleInUse) {
			return ErrRoleInUse, err
		}
		return ErrRoleDeleteFailed, err
	}

	return ginx.Result{Msg: "删除角色成功"}, nil
}

func (h *Handler) BatchDelete(ctx *ginx.Context, req BatchDeleteReq) (ginx.Result, error) {
	if _, err := h.svc.BatchDelete(ctx.Request.Context(), req.IDs); err != nil {
		if errors.Is(err, errs.ErrDeleteSystemRole) {
			return ErrReservedRoleCode, err
		}
		if errors.Is(err, errs.ErrRoleInUse) {
			return ErrRoleInUse, err
		}
		return ErrRoleDeleteFailed, err
	}

	return ginx.Result{Msg: "批量删除角色成功"}, nil
}

func (h *Handler) List(ctx *ginx.Context, req ListRoleRequest) (ginx.Result, error) {
	roles, total, err := h.svc.List(ctx.Request.Context(), req.Offset, req.Limit)
	if err != nil {
		return ErrRoleListFailed, err
	}

	return ginx.Result{
		Data: RetrieveRole{
			Roles: lo.Map(roles, func(src domain.Role, _ int) Role {
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
		if errors.Is(err, errs.ErrRoleSelfInheritance) {
			return ErrRoleSelfInheritance, err
		}
		if errors.Is(err, errs.ErrRoleCycleInheritance) {
			return ErrRoleCycleInheritance, err
		}
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
		Data: lo.Map(infos, func(src domain.InheritanceInfo, _ int) RoleInheritanceInfo {
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
	_, err := h.permSvc.AssignRolesToUser(ctx.Request.Context(), req.Usernames, req.RoleCodes)
	if err != nil {
		return ErrRoleAssignFailed, err
	}

	return ginx.Result{Msg: "批量分配成功"}, nil
}

func (h *Handler) BatchUnassignRole(ctx *ginx.Context, req BatchUnassignRoleRequest) (ginx.Result, error) {
	_, err := h.permSvc.RemoveRolesFromUser(ctx.Request.Context(), req.Usernames, req.RoleCodes)
	if err != nil {
		if errors.Is(err, errs.ErrPersonalTenantAdminUnassignForbidden) {
			return ErrPersonalTenantAdminUnassignForbidden, err
		}
		return ErrRoleAssignFailed, err
	}

	return ginx.Result{Msg: "批量移除成功"}, nil
}

func (h *Handler) UnassignRole(ctx *ginx.Context, req UnassignRoleRequest) (ginx.Result, error) {
	_, err := h.permSvc.RemoveRolesFromUser(ctx.Request.Context(), []string{req.Username}, []string{req.RoleCode})
	if err != nil {
		if errors.Is(err, errs.ErrPersonalTenantAdminUnassignForbidden) {
			return ErrPersonalTenantAdminUnassignForbidden, err
		}
		return ErrRoleAssignFailed, err
	}

	return ginx.Result{Msg: "移除成功"}, nil
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
		ID:    src.ID,
		Code:  src.Code,
		Name:  src.Name,
		Desc:  src.Desc,
		Type:  src.Type,
		Ctime: src.Ctime,
		Utime: src.Utime,
		InlinePolicies: lo.Map(src.InlinePolicies, func(src domain.Policy, _ int) Policy {
			return h.toPolicyVO(src)
		}),
	}
}

func (h *Handler) toPolicyVO(p domain.Policy) Policy {
	return Policy{
		Name: p.Name,
		Code: p.Code,
		Statement: lo.Map(p.Statement, func(s domain.Statement, _ int) Statement {
			return Statement{
				Effect:      string(s.Effect),
				Action:      s.Action,
				Resource:    s.Resource,
				Condition:   s.Condition,
				AccessScope: s.AccessScope,
			}
		}),
	}
}

func (h *Handler) toServiceSummaryVOs(summaries []domain.PolicyServiceSummary) []ServiceSummary {
	return lo.Map(summaries, func(src domain.PolicyServiceSummary, _ int) ServiceSummary {
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
			Actions: lo.Map(src.Actions, func(pct domain.GrantedAction, _ int) ActionDetail {
				// 格式化资源
				resStr := strings.Join(pct.Resource, ", ")

				// 格式化条件
				condStr := "-"
				if pct.Condition != nil {
					b, _ := json.Marshal(pct.Condition)
					condStr = string(b)
				}
				accessScopeStr := "-"
				if pct.AccessScope != nil {
					b, _ := json.Marshal(pct.AccessScope)
					accessScopeStr = string(b)
				}

				return ActionDetail{
					Code:        pct.Code,
					Name:        pct.Name,
					Group:       pct.Group,
					Resource:    resStr,
					Condition:   condStr,
					AccessScope: accessScopeStr,
				}
			}),
		}
	})
}
