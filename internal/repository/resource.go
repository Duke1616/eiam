package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
)

// IResourceRepository 物理资源仓库，负责全量 Menu 和 API 资产的底数管理
type IResourceRepository interface {
	// CreateAPI 录入一个新的物理接口资产
	CreateAPI(ctx context.Context, a domain.API) (int64, error)
	// FindAPIByPath 根据服务名、方法和路径精确匹配一个物理接口
	FindAPIByPath(ctx context.Context, service, method, path string) (domain.API, error)
	// ListAllAPIs 列出系统中注册的所有接口清单
	ListAllAPIs(ctx context.Context) ([]domain.API, error)

	// CreateMenu 录入一个新的前端菜单资源
	CreateMenu(ctx context.Context, m domain.Menu) (int64, error)
	// ListMenus 获取指定租户下的全量菜单树的基础数据
	ListMenus(ctx context.Context, tenantId int64) ([]domain.Menu, error)
}

type ResourceRepository struct {
	dao dao.IResourceDAO
}

// NewResourceRepository 创建资源仓库实例
func NewResourceRepository(dao dao.IResourceDAO) IResourceRepository {
	return &ResourceRepository{dao: dao}
}

// CreateAPI 实现 API 资产落地
func (r *ResourceRepository) CreateAPI(ctx context.Context, a domain.API) (int64, error) {
	return r.dao.InsertAPI(ctx, dao.API{
		Service: a.Service,
		Name:    a.Name,
		Method:  a.Method,
		Path:    a.Path,
	})
}

// FindAPIByPath 执行接口物理路径查重与匹配
func (r *ResourceRepository) FindAPIByPath(ctx context.Context, service, method, path string) (domain.API, error) {
	// NOTE: 在实际高性能场景下，这里建议使用 Radix Tree 或 Map 缓存全量 API 路径
	apis, err := r.dao.ListAllAPIs(ctx)
	if err != nil {
		return domain.API{}, err
	}
	for _, a := range apis {
		if a.Service == service && a.Method == method && a.Path == path {
			return domain.API{
				ID:      a.Id,
				Service: a.Service,
				Name:    a.Name,
				Method:  a.Method,
				Path:    a.Path,
				Ctime:   a.Ctime,
				Utime:   a.Utime,
			}, nil
		}
	}
	return domain.API{}, nil
}

// ListAllAPIs 获取系统物理边界清单
func (r *ResourceRepository) ListAllAPIs(ctx context.Context) ([]domain.API, error) {
	apis, err := r.dao.ListAllAPIs(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]domain.API, 0, len(apis))
	for _, a := range apis {
		res = append(res, domain.API{
			ID:      a.Id,
			Service: a.Service,
			Name:    a.Name,
			Method:  a.Method,
			Path:    a.Path,
			Ctime:   a.Ctime,
			Utime:   a.Utime,
		})
	}
	return res, nil
}

// CreateMenu 实现菜单资源落地
func (r *ResourceRepository) CreateMenu(ctx context.Context, m domain.Menu) (int64, error) {
	return r.dao.InsertMenu(ctx, dao.Menu{
		ParentId:  m.ParentID,
		TenantId:  m.TenantID,
		Name:      m.Name,
		Path:      m.Path,
		Component: m.Component,
		Icon:      m.Icon,
		Sort:      m.Sort,
		Hidden:    m.Hidden,
	})
}

// ListMenus 获取该租户在系统中能看到的全部菜单底表
func (r *ResourceRepository) ListMenus(ctx context.Context, tenantId int64) ([]domain.Menu, error) {
	menus, err := r.dao.ListMenusByTenant(ctx, tenantId)
	if err != nil {
		return nil, err
	}
	res := make([]domain.Menu, 0, len(menus))
	for _, m := range menus {
		res = append(res, domain.Menu{
			ID:        m.Id,
			ParentID:  m.ParentId,
			TenantID:  m.TenantId,
			Name:      m.Name,
			Path:      m.Path,
			Component: m.Component,
			Icon:      m.Icon,
			Sort:      m.Sort,
			Hidden:    m.Hidden,
			Ctime:     m.Ctime,
			Utime:     m.Utime,
		})
	}
	return res, nil
}
