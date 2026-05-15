package resource

import (
	"context"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/samber/lo"
)

// Reconciler 资产对账引擎接口
type Reconciler interface {
	// Reconcile 执行最终一致性对账
	Reconcile(ctx context.Context, req capability.SyncRequest) error
}

type defaultReconciler struct {
	permRepo repository.IPermissionRepository
	resRepo  repository.IResourceRepository
}

// NewReconciler 构建对账引擎
func NewReconciler(permRepo repository.IPermissionRepository, resRepo repository.IResourceRepository) Reconciler {
	return &defaultReconciler{
		permRepo: permRepo,
		resRepo:  resRepo,
	}
}

func (r *defaultReconciler) Reconcile(ctx context.Context, req capability.SyncRequest) error {
	// 1. 转换逻辑权限数据模型
	perms := lo.Map(req.Permissions, func(p capability.Permission, _ int) domain.Permission {
		return domain.Permission{
			Service: req.Service,
			Code:    p.Code,
			Name:    p.Name,
			Group:   p.Group,
			Needs:   p.Needs,
			Scope:   p.Scope,
		}
	})

	// 2. 转换物理接口数据模型
	apis := lo.Map(req.APIs, func(api capability.ResourceInfo, _ int) domain.API {
		return domain.API{
			Service: req.Service,
			Name:    api.Name,
			Method:  api.Method,
			Path:    api.Path,
		}
	})

	// 3. 转换菜单数据模型并打平
	menus := r.mapMenus(req.Service, req.Menus).Flatten(req.Service)

	// 4. 执行对账同步（逻辑权限、物理 API、菜单资产分别原子化）
	if err := r.permRepo.SyncPermissions(ctx, req.Service, perms); err != nil {
		return fmt.Errorf("对账逻辑权限点失败: %w", err)
	}

	if err := r.resRepo.SyncAPIs(ctx, req.Service, apis); err != nil {
		return fmt.Errorf("对账 API 资产失败: %w", err)
	}

	if err := r.resRepo.SyncMenus(ctx, req.Service, menus); err != nil {
		return fmt.Errorf("对账菜单资产失败: %w", err)
	}

	// 5. 执行资源绑定 (逻辑染色)
	bindings := make(map[string][]string)

	// 扫描 req.APIs 来构建绑定关系
	for _, a := range req.APIs {
		if a.Code != "" {
			// 构造 URN
			urn := domain.API{Service: req.Service, Method: a.Method, Path: a.Path}.URN()
			bindings[a.Code] = append(bindings[a.Code], urn)
		}
	}

	if len(bindings) > 0 {
		if err := r.permRepo.BatchBindResources(ctx, bindings); err != nil {
			return fmt.Errorf("资源绑定染色失败: %w", err)
		}
	}

	return nil
}

func (r *defaultReconciler) mapMenus(service string, menus []capability.Menu) domain.MenuTree {
	return lo.Map(menus, func(m capability.Menu, _ int) *domain.Menu {
		return &domain.Menu{
			Service:        service,
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
			Children: r.mapMenus(service, m.Children),
		}
	})
}
