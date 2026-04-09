package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/ecodeclub/ekit/slice"
)

// IResourceRepository 物理资源仓库，负责全量 Menu 和 API 资产的底数管理
type IResourceRepository interface {
	// CreateAPI 录入一个新的物理接口资产
	CreateAPI(ctx context.Context, a domain.API) (int64, error)
	// BatchCreateAPI 批量录入物理接口资产
	BatchCreateAPI(ctx context.Context, apis []domain.API) error
	// FindAPIByPath 根据服务名、方法和路径精确匹配一个物理接口
	FindAPIByPath(ctx context.Context, service, method, path string) (domain.API, error)
	// ListAllAPIs 列出系统中注册的所有接口清单
	ListAllAPIs(ctx context.Context) ([]domain.API, error)
	// ListAPIsByService 获取指定服务的接口清单
	ListAPIsByService(ctx context.Context, service string) ([]domain.API, error)

	// UpsertMenu 智能更新录入菜单资产，基于 Name 匹配以保留原始 ID
	UpsertMenu(ctx context.Context, m *domain.Menu) error
	// SyncMenus 高性能同步菜单资产，基于领域对象自带的 ParentName 自动解析拓扑
	SyncMenus(ctx context.Context, menus domain.MenuList) error
	// ListAllMenus 获取系统中注册的所有全量菜单
	ListAllMenus(ctx context.Context) ([]domain.Menu, error)
	// GetMenu 根据 ID 获取菜单
	GetMenu(ctx context.Context, id int64) (domain.Menu, error)
	// ListMenusByParentID 获取指定父菜单下的所有直属子菜单
	ListMenusByParentID(ctx context.Context, parentID int64) ([]domain.Menu, error)

	// UpdateMenuSort 更新单个菜单排序分值与归属父节点 (原子操作)
	UpdateMenuSort(ctx context.Context, id int64, parentID int64, sortKey int64) error
	// BatchUpdateMenuSort 批量更新菜单排序分值（重平衡路径）
	BatchUpdateMenuSort(ctx context.Context, menus []domain.Menu) error
}

type ResourceRepository struct {
	dao dao.IResourceDAO
}

func NewResourceRepository(dao dao.IResourceDAO) IResourceRepository {
	return &ResourceRepository{dao: dao}
}

// SyncMenus 实现高性能的原子级资产同步 (领域驱动版)
func (r *ResourceRepository) SyncMenus(ctx context.Context, menus domain.MenuList) error {
	names := slice.Map(menus, func(_ int, m domain.Menu) string { return m.Name })

	return r.dao.Transaction(ctx, func(txCtx context.Context) error {
		// 元数据对齐
		daoEntities := slice.Map(menus, func(_ int, m domain.Menu) dao.Menu { return r.toDAOMenu(m) })
		if err := r.dao.BatchUpsertMenus(txCtx, daoEntities); err != nil {
			return err
		}

		// 拓扑对齐 (基于 ParentName 修正 ParentID)
		if err := r.alignTopology(txCtx, daoEntities, menus); err != nil {
			return err
		}

		// 孤儿清理
		return r.dao.DeleteMenusByNames(txCtx, names)
	})
}

func (r *ResourceRepository) alignTopology(ctx context.Context, entities []dao.Menu, source domain.MenuList) error {
	latest, err := r.dao.ListAllMenus(ctx)
	if err != nil {
		return err
	}
	nameMap := slice.ToMap(latest, func(m dao.Menu) string { return m.Name })

	for i := range entities {
		pName := source[i].ParentName
		if pName != "" {
			if parent, exists := nameMap[pName]; exists {
				entities[i].ParentId = parent.Id
			}
		} else {
			entities[i].ParentId = 0
		}
	}

	return r.dao.BatchUpsertMenus(ctx, entities)
}

// --- 其它方法保持简洁 ---

func (r *ResourceRepository) CreateAPI(ctx context.Context, a domain.API) (int64, error) {
	return r.dao.InsertAPI(ctx, dao.API{
		Service: a.Service,
		Name:    a.Name,
		Method:  a.Method,
		Path:    a.Path,
	})
}

func (r *ResourceRepository) BatchCreateAPI(ctx context.Context, apis []domain.API) error {
	daoApis := slice.Map(apis, func(_ int, a domain.API) dao.API {
		return dao.API{Service: a.Service, Name: a.Name, Method: a.Method, Path: a.Path}
	})
	return r.dao.BatchInsertAPI(ctx, daoApis)
}

func (r *ResourceRepository) FindAPIByPath(ctx context.Context, service, method, path string) (domain.API, error) {
	apis, err := r.dao.ListAllAPIs(ctx)
	if err != nil {
		return domain.API{}, err
	}
	for _, a := range apis {
		if a.Service == service && a.Method == method && a.Path == path {
			return r.toDomainAPI(a), nil
		}
	}
	return domain.API{}, nil
}

func (r *ResourceRepository) ListAllAPIs(ctx context.Context) ([]domain.API, error) {
	apis, err := r.dao.ListAllAPIs(ctx)
	if err != nil {
		return nil, err
	}
	return slice.Map(apis, func(_ int, a dao.API) domain.API { return r.toDomainAPI(a) }), nil
}

func (r *ResourceRepository) ListAPIsByService(ctx context.Context, service string) ([]domain.API, error) {
	apis, err := r.dao.ListAPIsByService(ctx, service)
	if err != nil {
		return nil, err
	}
	return slice.Map(apis, func(_ int, a dao.API) domain.API { return r.toDomainAPI(a) }), nil
}

func (r *ResourceRepository) UpsertMenu(ctx context.Context, m *domain.Menu) error {
	row, err := r.dao.FindMenuByName(ctx, m.Name)
	if err == nil {
		m.ID = row.Id
		return r.dao.UpdateMenu(ctx, r.toDAOMenu(*m))
	}

	id, err := r.dao.InsertMenu(ctx, r.toDAOMenu(*m))
	if err != nil {
		return err
	}
	m.ID = id
	return nil
}

func (r *ResourceRepository) ListAllMenus(ctx context.Context) ([]domain.Menu, error) {
	menus, err := r.dao.ListAllMenus(ctx)
	if err != nil {
		return nil, err
	}
	return slice.Map(menus, func(_ int, m dao.Menu) domain.Menu { return r.toDomainMenu(m) }), nil
}

func (r *ResourceRepository) GetMenu(ctx context.Context, id int64) (domain.Menu, error) {
	all, err := r.dao.ListAllMenus(ctx)
	if err != nil {
		return domain.Menu{}, err
	}
	for _, m := range all {
		if m.Id == id {
			return r.toDomainMenu(m), nil
		}
	}
	return domain.Menu{}, nil
}

func (r *ResourceRepository) ListMenusByParentID(ctx context.Context, parentID int64) ([]domain.Menu, error) {
	menus, err := r.dao.ListMenusByParentID(ctx, parentID)
	if err != nil {
		return nil, err
	}
	return slice.Map(menus, func(_ int, m dao.Menu) domain.Menu { return r.toDomainMenu(m) }), nil
}

func (r *ResourceRepository) UpdateMenuSort(ctx context.Context, id int64, parentID int64, sortKey int64) error {
	return r.dao.UpdateMenuSort(ctx, id, parentID, sortKey)
}

func (r *ResourceRepository) BatchUpdateMenuSort(ctx context.Context, menus []domain.Menu) error {
	daoMenus := slice.Map(menus, func(_ int, m domain.Menu) dao.Menu { return r.toDAOMenu(m) })
	return r.dao.BatchUpdateMenuSort(ctx, daoMenus)
}

// --- 转换助手 (Mapper) ---

func (r *ResourceRepository) toDAOMenu(m domain.Menu) dao.Menu {
	return dao.Menu{
		Id:             m.ID,
		ParentId:       m.ParentID,
		Name:           m.Name,
		Path:           m.Path,
		Component:      m.Component,
		Redirect:       m.Redirect,
		PermissionCode: m.PermissionCode,
		Sort:           m.Sort,
		Meta: sqlx.JSONColumn[dao.MenuMeta]{
			Valid: true,
			Val: dao.MenuMeta{
				Title:       m.Meta.Title,
				Icon:        m.Meta.Icon,
				IsHidden:    m.Meta.IsHidden,
				IsAffix:     m.Meta.IsAffix,
				IsKeepAlive: m.Meta.IsKeepAlive,
				Platforms:   m.Meta.Platforms,
			},
		},
	}
}

func (r *ResourceRepository) toDomainMenu(m dao.Menu) domain.Menu {
	return domain.Menu{
		ID:             m.Id,
		ParentID:       m.ParentId,
		Name:           m.Name,
		Path:           m.Path,
		Component:      m.Component,
		Redirect:       m.Redirect,
		PermissionCode: m.PermissionCode,
		Sort:           m.Sort,
		Meta: domain.MenuMeta{
			Title:       m.Meta.Val.Title,
			Icon:        m.Meta.Val.Icon,
			IsHidden:    m.Meta.Val.IsHidden,
			IsAffix:     m.Meta.Val.IsAffix,
			IsKeepAlive: m.Meta.Val.IsKeepAlive,
			Platforms:   m.Meta.Val.Platforms,
		},
		Ctime: m.Ctime,
		Utime: m.Utime,
	}
}

func (r *ResourceRepository) toDomainAPI(a dao.API) domain.API {
	return domain.API{
		ID:      a.Id,
		Service: a.Service,
		Name:    a.Name,
		Method:  a.Method,
		Path:    a.Path,
		Ctime:   a.Ctime,
		Utime:   a.Utime,
	}
}
