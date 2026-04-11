package permission

import (
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	permissionsvc "github.com/Duke1616/eiam/internal/service/permission"
	"github.com/ecodeclub/ekit/slice"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc  permissionsvc.IPermissionService
	sess session.Provider
}

func NewHandler(svc permissionsvc.IPermissionService, sess session.Provider) *Handler {
	return &Handler{
		svc:  svc,
		sess: sess,
	}
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/permission")

	// 核心业务：查询当前用户的权限资产（用于前端渲染菜单）
	g.GET("/menus", ginx.W(h.GetAuthorizedMenus))

	// 元数据管理：查询权限资产清单
	g.GET("/manifest", ginx.W(h.GetPermissionManifest))
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
			Services: slice.Map(reg.Services, func(idx int, src domain.ServiceNode) ServicePermissionEntry {
				return ServicePermissionEntry{
					Code: src.Code,
					Name: src.Name,
					Entries: slice.Map(src.Groups, func(idx int, g domain.GroupNode) Entry {
						return Entry{
							Name:    g.Name,
							Actions: g.Actions,
						}
					}),
				}
			}),
		},
	}, nil
}

func (h *Handler) toActionVOs(perms []domain.Permission) []Permission {
	return slice.Map(perms, func(idx int, p domain.Permission) Permission {
		return Permission{
			ID:      p.ID,
			Service: p.Service,
			Group:   p.Group,
			Code:    p.Code,
			Name:    p.Name,
		}
	})
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/permission")
	// 鉴权接口本身需要公开，因为 SDK 内部会带上 Token 并在逻辑内自行校验
	g.POST("/check_login", ginx.W(h.CheckLogin))
	g.POST("/check_policy", ginx.B[CheckPolicyReq](h.CheckPolicy))
}

// CheckLogin 实现 SDK 的登录状态校验
func (h *Handler) CheckLogin(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := h.sess.Get(&gctx.Context{Context: ctx.Context})
	if err != nil {
		return ErrUnauthenticated, err
	}

	// 提取租户 ID 并返回给 SDK
	claims := sess.Claims()
	return ginx.Result{
		Code: 0,
		Data: map[string]any{
			"uid":       claims.Uid,
			"tenant_id": claims.Data["tenant_id"],
		},
	}, nil
}

// CheckPolicy 实现 SDK 的全链路权限判定决策
func (h *Handler) CheckPolicy(ctx *ginx.Context, req CheckPolicyReq) (ginx.Result, error) {
	// 1. 获取当前用户和租户上下文
	sess, err := h.sess.Get(&gctx.Context{Context: ctx.Context})
	if err != nil {
		return ErrUnauthenticated, err
	}

	// 2. 调用全链路 CheckAPI 逻辑 (物理 Path -> 能力码 -> 逻辑权限判定)
	allowed, err := h.svc.CheckAPI(ctx.Context, sess.Claims().Uid, req.Service, req.Method, req.Path)
	if err != nil {
		return ginx.Result{
			Code: 0,
			Data: AuthorizeResult{
				Allowed: false,
				Reason:  fmt.Sprintf("鉴权逻辑校验出错: %v", err),
			},
		}, nil
	}

	// 3. 如果物理 API 校验通过，还需要针对具体的 Resource 维度进行逻辑判定 (OPA 处理)
	// 如果 req.Resource != "*"，我们需要额外加一道特定资源的 OPA 判定
	// 此处目前保留简化实现，物理 API 通过即通过

	return ginx.Result{
		Code: 0,
		Data: AuthorizeResult{
			Allowed: allowed,
		},
	}, nil
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

	return ginx.Result{Data: h.toMenuVOs(menus)}, nil
}

func (h *Handler) toMenuVOs(menus domain.MenuTree) []Menu {
	return slice.Map(menus, func(idx int, m *domain.Menu) Menu {
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
