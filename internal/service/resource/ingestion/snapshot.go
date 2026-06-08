package ingestion

import (
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/web/capability"
)

// Snapshot 定义了资源录入的内部统一资产快照。
// 所有外部来源（SDK 协议、本地 YAML）在进入处理引擎前，必须先归一化为 Snapshot。
type Snapshot struct {
	Service     string
	Permissions []domain.Permission
	APIs        []domain.API
	Menus       domain.MenuTree
	// Bindings 预解析的 PermissionCode -> ResourceURN 映射关系，
	// 由 Snapshot 在构建时从 APIs.Code 和 Menus.PermissionCode 中一次性提取。
	Bindings map[string][]string
}

// FromSyncRequest 将 SDK 协议的 SyncRequest 转换为内部统一的 Snapshot。
// 转换过程中一次性完成 domain 模型映射与 binding 关系解析，避免后续重复转换。
func FromSyncRequest(req capability.SyncRequest) Snapshot {
	// 1. 转换逻辑权限点
	perms := make([]domain.Permission, len(req.Permissions))
	for i, p := range req.Permissions {
		perms[i] = domain.Permission{
			Service: req.Service,
			Code:    p.Code,
			Name:    p.Name,
			Group:   p.Group,
			Needs:   p.Needs,
			Scope:   p.Scope,
			Sort:    p.Sort,
		}
	}

	// 2. 转换物理接口并预解析 API 绑定关系
	bindings := make(map[string][]string)
	apis := make([]domain.API, len(req.APIs))
	for i, a := range req.APIs {
		apis[i] = domain.API{
			Service: req.Service,
			Name:    a.Name,
			Method:  a.Method,
			Path:    a.Path,
		}
		if a.Code != "" {
			urn := domain.API{Service: req.Service, Method: a.Method, Path: a.Path}.URN()
			bindings[a.Code] = append(bindings[a.Code], urn)
		}
	}

	// 3. 转换菜单并预解析菜单绑定关系
	menus := mapMenus(req.Menus)
	for _, m := range menus.Flatten() {
		if m.PermissionCode != "" {
			bindings[m.PermissionCode] = append(bindings[m.PermissionCode], m.URN())
		}
	}

	return Snapshot{
		Service:     req.Service,
		Permissions: perms,
		APIs:        apis,
		Menus:       menus,
		Bindings:    bindings,
	}
}

// mapMenus 将 capability 层的菜单模型递归转换为 domain 菜单树。
// 该逻辑从原 reconciler.go 迁移至此，作为转换层的唯一实现。
func mapMenus(menus []capability.Menu) domain.MenuTree {
	result := make(domain.MenuTree, len(menus))
	for i, m := range menus {
		result[i] = &domain.Menu{
			Name:           m.Name,
			Path:           m.Path,
			Component:      m.Component,
			Redirect:       m.Redirect,
			PermissionCode: m.PermissionCode,
			Sort:           m.Sort,
			Meta: domain.MenuMeta{
				Title:       m.Meta.Title,
				Icon:        m.Meta.Icon,
				IsHidden:    m.Meta.IsHidden,
				IsAffix:     m.Meta.IsAffix,
				IsKeepAlive: m.Meta.IsKeepAlive,
				Platforms:   m.Meta.Platforms,
			},
			Children: mapMenus(m.Children),
		}
	}
	return result
}
