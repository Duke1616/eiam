package permission

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/pkg/middleware"
	permissionsvc "github.com/Duke1616/eiam/internal/service/permission"
	permcontract "github.com/Duke1616/eiam/pkg/contract/permission"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

type Handler struct {
	capability.IRegistry
	svc     permissionsvc.IPermissionService
	matcher middleware.IAuditMatcher
}

func NewHandler(svc permissionsvc.IPermissionService, matcher middleware.IAuditMatcher) *Handler {
	return &Handler{
		svc:       svc,
		matcher:   matcher,
		IRegistry: capability.NewRegistry("iam", "permission", "权限管理"),
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/permission")
	// 鉴权接口本身需要公开，因为 SDK 内部会带上 Token 并在逻辑内自行校验
	g.POST("/check_login", ginx.W(h.CheckLogin))
	g.POST("/check_policy", ginx.B[CheckPolicyReq](h.CheckPolicy))
}

func (h *Handler) IdentityRoutes(server *gin.Engine) {
	g := server.Group("/api/permission")

	// 核心业务：查询当前用户的权限资产、用于前端渲染菜单
	g.GET("/menus", ginx.S(h.GetAuthorizedMenus))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/permission")

	// 元数据管理：查询权限资产清单
	g.GET("/manifest", h.Define("权限资产清单", "manifest").
		Needs(permcontract.Permission.MenusByUrns).
		Bind(ginx.W(h.GetPermissionManifest)),
	)

	// 授权治理：查询全量授权关系列表
	g.POST("/authorizations", h.Define("授权治理列表", "view_authorizations").
		Bind(ginx.B[AuthorizationQueryReq](h.ListAuthorizations)),
	)

	// 授权治理：查询可授权主体 (用户/角色)
	g.POST("/subjects/search", h.Define("搜索授权主体", "search_subjects").
		Bind(ginx.B[SearchSubjectsReq](h.SearchSubjects)),
	)

	// 批量根据 URN 查询菜单详情
	g.POST("/menus/by_urns", h.Define("批量根据 URN 查询菜单详情", "menus_by_urns").
		NoSync().
		Bind(ginx.B[QueryMenusByURNsReq](h.ListMenusByURNs)),
	)
}

func (h *Handler) GetPermissionManifest(ctx *ginx.Context) (ginx.Result, error) {
	// 1. 获取领域层归一化 Manifest 数据
	reg, err := h.svc.GetPermissionManifest(ctx.Request.Context())
	if err != nil {
		return ginx.Result{Msg: "获取权限清单失败"}, err
	}

	// 2. 映射为 Web VO
	return ginx.Result{
		Data: Manifest{
			Actions: h.toActionVOs(reg.Permissions),
			Services: lo.Map(reg.Services, func(src domain.ServiceNode, _ int) ServicePermissionEntry {
				return ServicePermissionEntry{
					Code:    src.Code,
					Name:    src.Name,
					Entries: h.toEntryVOs(src.Groups),
				}
			}),
		},
	}, nil
}

func (h *Handler) toEntryVOs(nodes []domain.GroupNode) []Entry {
	if len(nodes) == 0 {
		return nil
	}
	return lo.Map(nodes, func(g domain.GroupNode, _ int) Entry {
		return Entry{
			Name:     g.Name,
			Actions:  g.Actions,
			Children: h.toEntryVOs(g.Children),
		}
	})
}

func (h *Handler) toActionVOs(perms []domain.Permission) []Permission {
	return lo.Map(perms, func(p domain.Permission, _ int) Permission {
		return Permission{
			ID:                 p.ID,
			Service:            p.Service,
			Group:              p.Group,
			Code:               p.Code,
			Name:               p.Name,
			HasMenu:            p.HasMenu,
			MenuURNs:           p.MenuURNs,
			AccessScopePresets: p.AccessScopePresets,
		}
	})
}

// CheckLogin 实现 SDK 的登录状态校验
func (h *Handler) CheckLogin(ctx *ginx.Context) (ginx.Result, error) {
	_, claims, err := h.ctxWithAuth(ctx)
	if err != nil {
		return ErrUnauthenticated, err
	}

	return ginx.Result{
		Code: 0,
		Data: map[string]any{
			"uid":       claims.Uid,
			"tenant_id": claims.Data["tenant_id"],
			"username":  claims.Data["username"],
		},
	}, nil
}

// CheckPolicy 实现 SDK 的全链路权限判定决策
func (h *Handler) CheckPolicy(ctx *ginx.Context, req CheckPolicyReq) (ginx.Result, error) {
	// 1. 获取带有身份信息的 Context 和用户名
	newCtx, claims, err := h.ctxWithAuth(ctx)
	if err != nil {
		return ErrUnauthenticated, err
	}

	username := claims.Data["username"]

	// 2. 调用全链路 CheckAPI 逻辑 (物理 Path -> 能力码 -> 逻辑权限判定)
	decision, err := h.svc.CheckAPIDecision(newCtx, username, req.Service, req.Method, req.Path)
	if err != nil {
		return ginx.Result{
			Code: 0,
			Data: CheckPolicyResp{
				Decision: AuthorizeResult{ReasonCode: pbac.ReasonEvaluationError, Reason: "authorization evaluation failed"},
				Audit:    false,
			},
		}, nil
	}

	audit := h.matcher.ShouldAuditMethod(req.Method) && !h.matcher.IsIgnoredPath(req.Path)

	return ginx.Result{
		Code: 0,
		Data: CheckPolicyResp{
			Decision: decision,
			Audit:    audit,
		},
	}, nil
}

// ctxWithAuth 辅助方法：从请求中提取 Session 并确保 Context 带有身份信息
func (h *Handler) ctxWithAuth(ctx *ginx.Context) (context.Context, session.Claims, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return nil, session.Claims{}, err
	}

	claims := sess.Claims()
	reqCtx := ctx.Request.Context()

	// 优先复用全局中间件已注入的租户与用户上下文，缺失时从 Claims 回退注入
	if ctxutil.GetTenantID(reqCtx) == 0 {
		tid, _ := claims.Get("tenant_id").AsInt64()
		reqCtx = ctxutil.WithUserAndTenant(reqCtx, claims.Uid, tid)
	}

	return reqCtx, claims, nil
}

func (h *Handler) GetAuthorizedMenus(ctx *ginx.Context, sess session.Session) (ginx.Result, error) {
	username, ok := sess.Claims().Data["username"]
	if !ok {
		return ErrUnauthenticated, nil
	}

	menus, err := h.svc.GetAuthorizedMenus(ctx.Request.Context(), username)
	if err != nil {
		return ErrAuthMenuFailed, err
	}

	return ginx.Result{Data: h.toMenuVOs(menus)}, nil
}

func (h *Handler) ListMenusByURNs(ctx *ginx.Context, req QueryMenusByURNsReq) (ginx.Result, error) {
	menus, err := h.svc.GetMenusByURNs(ctx.Request.Context(), req.URNs)
	if err != nil {
		return ginx.Result{Msg: "根据 URN 查询菜单信息失败"}, err
	}

	menuTree := make(domain.MenuTree, 0, len(menus))
	for i := range menus {
		menuTree = append(menuTree, &menus[i])
	}

	return ginx.Result{Data: h.toMenuVOs(menuTree)}, nil
}

func (h *Handler) toMenuVOs(menus domain.MenuTree) []Menu {
	// ... (代码逻辑保持不变)
	return lo.Map(menus, func(m *domain.Menu, _ int) Menu {
		return Menu{
			ID:        m.ID,
			ParentID:  m.ParentID,
			Name:      m.Name,
			Path:      m.Path,
			Component: m.Component,
			Redirect:  m.Redirect,
			Meta: Meta{
				Title:       m.Meta.Title,
				Icon:        m.Meta.Icon,
				IsHidden:    m.Meta.IsHidden,
				IsKeepAlive: m.Meta.IsKeepAlive,
				IsAffix:     m.Meta.IsAffix,
				Platforms:   m.Meta.Platforms,
			},
			Children: h.toMenuVOs(m.Children),
		}
	})
}

func (h *Handler) ListAuthorizations(ctx *ginx.Context, req AuthorizationQueryReq) (ginx.Result, error) {
	// 1. 设置默认分页
	if req.Limit <= 0 {
		req.Limit = 10
	}

	// 2. 调用 Service 获取数据
	auths, total, err := h.svc.ListAuthorizations(ctx.Request.Context(), domain.AuthorizationQuery{
		Offset:  req.Offset,
		Limit:   req.Limit,
		Keyword: req.Keyword,
		SubType: domain.AuthorizationSubType(req.SubType),
		ObjType: domain.AuthorizationObjType(req.ObjType),
	})
	if err != nil {
		return ginx.Result{Msg: "获取授权列表失败"}, err
	}

	// 3. 映射为 Web VO
	return ginx.Result{
		Data: AuthorizationResp{
			Total: total,
			Authorizations: lo.Map(auths, func(src domain.Authorization, _ int) Authorization {
				return Authorization{
					ID:          src.ID,
					Subject:     src.Subject.ID,
					Target:      src.Target.ID,
					SubType:     src.Subject.Type,
					ObjType:     src.Target.Type,
					SubjectName: src.SubjectName,
					TargetName:  src.TargetName,
					Note:        src.Note,
					Scope:       src.Scope,
					Ctime:       src.Ctime,
				}
			}),
		},
	}, nil
}

func (h *Handler) SearchSubjects(ctx *ginx.Context, req SearchSubjectsReq) (ginx.Result, error) {
	subjects, total, err := h.svc.SearchSubjects(ctx.Request.Context(), req.Keyword, req.SubType, req.Offset, req.Limit)
	if err != nil {
		return ginx.Result{Msg: "搜索主体失败"}, err
	}

	return ginx.Result{
		Data: SearchSubjectsResp{
			Total: total,
			Subjects: lo.Map(subjects, func(src domain.Subject, _ int) Subject {
				return Subject{
					Type: src.Type,
					Id:   src.ID,
					Name: src.Name,
					Desc: src.Desc,
				}
			}),
		},
	}, nil
}
