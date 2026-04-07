package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
)

// IResourceRepository 物理资源仓库，负责全量 Menu 和 API 资产的底数管理
type IResourceRepository interface {
	// CreateAPI 录入一个新的物理接口资产
	CreateAPI(ctx context.Context, a domain.API) (int64, error)
	// FindAPIByPath 根据服务名、方法和路径精确匹配一个物理接口
	FindAPIByPath(ctx context.Context, service, method, path string) (domain.API, error)
	// ListAllAPIs 列出系统中注册的所有接口清单
	ListAllAPIs(ctx context.Context) ([]domain.API, error)

	// UpsertMenu 智能更新录入菜单资产，基于 Name 匹配以保留原始 ID
	UpsertMenu(ctx context.Context, m *domain.Menu) error
	// SyncMenuTree 高性能同步菜单树，消除 N+1 查询
	SyncMenuTree(ctx context.Context, menus []*domain.Menu) error
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

// UpsertMenu 核心幂等同步逻辑：Name 存在则更新，不存在则新增
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

// SyncMenuTree 实现高性能的原子级资产同步
func (r *ResourceRepository) SyncMenuTree(ctx context.Context, menus []*domain.Menu) error {
	// 1. 批量预加载：一次性拉取全量底数，构建 O(1) 内存索引
	all, err := r.dao.ListAllMenus(ctx)
	if err != nil {
		return err
	}
	index := make(map[string]int64, len(all))
	for _, m := range all {
		index[m.Name] = m.Id
	}

	// 2. 递归对齐：在内存中完成“资产存在性”判定，避免 N+1 IO
	return r.recursiveSync(ctx, menus, 0, index)
}

func (r *ResourceRepository) recursiveSync(ctx context.Context, menus []*domain.Menu, parentID int64, index map[string]int64) error {
	for _, m := range menus {
		m.ParentID = parentID
		// 内存级匹配，无需数据库交互
		if id, ok := index[m.Name]; ok {
			m.ID = id
			if err := r.dao.UpdateMenu(ctx, r.toDAOMenu(*m)); err != nil {
				return err
			}
		} else {
			id, err := r.dao.InsertMenu(ctx, r.toDAOMenu(*m))
			if err != nil {
				return err
			}
			m.ID = id
		}

		if len(m.Children) > 0 {
			if err := r.recursiveSync(ctx, m.Children, m.ID, index); err != nil {
				return err
			}
		}
	}
	return nil
}

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

// ListAllMenus 获取系统中注册的所有全量菜单
func (r *ResourceRepository) ListAllMenus(ctx context.Context) ([]domain.Menu, error) {
	menus, err := r.dao.ListAllMenus(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]domain.Menu, 0, len(menus))
	for _, m := range menus {
		res = append(res, r.toDomainMenu(m))
	}
	return res, nil
}

func (r *ResourceRepository) GetMenu(ctx context.Context, id int64) (domain.Menu, error) {
	// 暂时简单复用全量列表查找，或在 DAO 增加单个查询
	// 为高性能考虑建议在 IResourceDAO 补充 FindMenuByID
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
	res := make([]domain.Menu, 0, len(menus))
	for _, m := range menus {
		res = append(res, r.toDomainMenu(m))
	}
	return res, nil
}

func (r *ResourceRepository) UpdateMenuSort(ctx context.Context, id int64, parentID int64, sortKey int64) error {
	return r.dao.UpdateMenuSort(ctx, id, parentID, sortKey)
}

func (r *ResourceRepository) BatchUpdateMenuSort(ctx context.Context, menus []domain.Menu) error {
	daoMenus := make([]dao.Menu, 0, len(menus))
	for _, m := range menus {
		daoMenus = append(daoMenus, r.toDAOMenu(m))
	}
	return r.dao.BatchUpdateMenuSort(ctx, daoMenus)
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
