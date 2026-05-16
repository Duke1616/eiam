package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Menu 菜单资源表 (物理元数据)
// 菜单是平台级 UI 资源，Name 全局唯一，Service 降级为普通列 (仅用于孤儿标记分组)
type Menu struct {
	Id             int64                     `gorm:"type:bigint;primaryKey;autoIncrement;comment:'菜单ID'"`
	ParentId       int64                     `gorm:"type:bigint;not null;default:0;index:idx_parent_id;comment:'父菜单ID'"`
	Service        string                    `gorm:"type:varchar(128);not null;default:'eiam';index:idx_service;comment:'所属服务 (仅分组用途)'"`
	Name           string                    `gorm:"type:varchar(255);not null;uniqueIndex:uni_name;comment:'名称 (全局唯一)'"`
	Path           string                    `gorm:"type:varchar(255);comment:'前端路由地址'"`
	Component      string                    `gorm:"type:varchar(255);comment:'前端组件地址'"`
	Redirect       string                    `gorm:"type:varchar(255);comment:'重定向地址'"`
	PermissionCode string                    `gorm:"type:varchar(128);comment:'资源关联的权限码声明'"`
	Sort           int64                     `gorm:"type:bigint;not null;default:0;comment:'排序号'"`
	Meta           sqlx.JSONColumn[MenuMeta] `gorm:"type:json;comment:'展示元数据'"`
	Ctime          int64                     `gorm:"type:bigint;not null;comment:'创建时间'"`
	Utime          int64                     `gorm:"type:bigint;not null;comment:'更新时间'"`
	Status         uint8                     `gorm:"type:tinyint;not null;default:1;comment:'状态 1-正常 2-孤儿'"`
}

const (
	MenuStatusActive uint8 = 1
	MenuStatusOrphan uint8 = 2
)

// MenuMeta 镜像结构，用于 JSON 序列化
type MenuMeta struct {
	Title       string   `json:"title"`
	Icon        string   `json:"icon"`
	IsHidden    bool     `json:"is_hidden"`
	IsAffix     bool     `json:"is_affix"`
	IsKeepAlive bool     `json:"is_keepalive"`
	Platforms   []string `json:"platforms"`
}

// API 接口资源表 (物理元数据)
type API struct {
	Id      int64  `gorm:"type:bigint;primaryKey;autoIncrement;comment:'接口ID'"`
	Service string `gorm:"type:varchar(128);not null;uniqueIndex:idx_service_method_path;comment:'所属服务'"`
	Name    string `gorm:"type:varchar(255);not null;comment:'接口描述名称'"`
	Method  string `gorm:"type:varchar(16);not null;uniqueIndex:idx_service_method_path;comment:'HTTP动词'"`
	Path    string `gorm:"type:varchar(255);not null;uniqueIndex:idx_service_method_path;comment:'接口路径'"`
	Ctime   int64  `gorm:"type:bigint;not null;comment:'创建时间'"`
	Utime   int64  `gorm:"type:bigint;not null;comment:'更新时间'"`
	Status  uint8  `gorm:"type:tinyint;not null;default:1;comment:'状态 1-正常 2-孤儿'"`
}

const (
	APIStatusActive uint8 = 1
	APIStatusOrphan uint8 = 2
)

// IResourceDAO 定义了物理资源 (Menu/API) 的底层持久化接口。
// 所有查询方法默认仅返回 status = Active 的有效资产，已标记为 orphan 的数据对业务层不可见。
type IResourceDAO interface {
	// InsertMenu 插入一条菜单记录，返回自增 ID
	InsertMenu(ctx context.Context, m Menu) (int64, error)
	// UpdateMenu 根据 ID 更新菜单的完整字段
	UpdateMenu(ctx context.Context, m Menu) error
	// FindMenuByName 根据菜单名称精确查找（不区分 active/orphan，用于 Upsert 场景）
	FindMenuByName(ctx context.Context, name string) (Menu, error)
	// ListAllMenus 列出所有状态为 Active 的菜单，按 sort 升序排列
	ListAllMenus(ctx context.Context) ([]Menu, error)
	// ListMenusByParentID 列出指定父菜单下所有状态为 Active 的子菜单
	ListMenusByParentID(ctx context.Context, parentID int64) ([]Menu, error)
	// ListMenusByNames 根据名称列表批量查找状态为 Active 的菜单
	ListMenusByNames(ctx context.Context, names []string) ([]Menu, error)

	// UpdateMenuSort 更新单个菜单的 parent_id 与 sort（原子操作）
	UpdateMenuSort(ctx context.Context, id int64, parentID int64, sort int64) error
	// BatchUpdateMenuSort 批量更新菜单排序（用于重平衡）
	BatchUpdateMenuSort(ctx context.Context, menus []Menu) error
	// MarkMenusAsOrphan 将不在 names 列表中的菜单标记为 orphan 状态
	MarkMenusAsOrphan(ctx context.Context, names []string) error
	// BatchUpsertMenus 基于 name 唯一键批量插入或更新菜单，并强制重置 status = Active
	BatchUpsertMenus(ctx context.Context, menus []Menu) error

	// InsertAPI 插入一条接口记录，返回自增 ID
	InsertAPI(ctx context.Context, a API) (int64, error)
	// BatchInsertAPI 批量插入或更新接口，并强制重置 status = Active
	BatchInsertAPI(ctx context.Context, apis []API) error
	// FindAPIByPath 根据 service + method + path 精确查找状态为 Active 的接口
	// 未找到时返回 gorm.ErrRecordNotFound
	FindAPIByPath(ctx context.Context, service, method, path string) (API, error)
	// ListAllAPIs 列出所有状态为 Active 的接口
	ListAllAPIs(ctx context.Context) ([]API, error)
	// ListAPIsByService 列出指定服务下所有状态为 Active 的接口
	ListAPIsByService(ctx context.Context, service string) ([]API, error)
	// DeleteAPIsByServiceAndURNs 删除指定服务下不在给定 URN 列表中的接口（物理删除）
	DeleteAPIsByServiceAndURNs(ctx context.Context, service string, urns []string) error
	// MarkAPIsAsOrphan 将指定服务下不在 URN 列表中的接口标记为 orphan 状态
	MarkAPIsAsOrphan(ctx context.Context, service string, urns []string) error

	// Transaction 在事务上下文中执行 fn，通过 ctx 传递 tx 对象
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}

type ResourceDAO struct {
	db *gorm.DB
}

type resTxKey struct{}

func (d *ResourceDAO) getDB(ctx context.Context) *gorm.DB {
	tx, ok := ctx.Value(resTxKey{}).(*gorm.DB)
	if ok {
		return tx
	}
	return d.db.WithContext(ctx)
}

func NewResourceDAO(db *gorm.DB) IResourceDAO {
	return &ResourceDAO{db: db}
}

func (d *ResourceDAO) InsertMenu(ctx context.Context, m Menu) (int64, error) {
	now := time.Now().UnixMilli()
	m.Ctime = now
	m.Utime = now
	err := d.getDB(ctx).Create(&m).Error
	return m.Id, err
}

func (d *ResourceDAO) UpdateMenu(ctx context.Context, m Menu) error {
	return d.getDB(ctx).Model(&Menu{}).Where("id = ?", m.Id).Updates(map[string]interface{}{
		"parent_id":       m.ParentId,
		"name":            m.Name,
		"path":            m.Path,
		"component":       m.Component,
		"redirect":        m.Redirect,
		"permission_code": m.PermissionCode,
		"sort":            m.Sort,
		"meta":            m.Meta,
		"utime":           time.Now().UnixMilli(),
	}).Error
}

func (d *ResourceDAO) FindMenuByName(ctx context.Context, name string) (Menu, error) {
	var m Menu
	err := d.getDB(ctx).Where("name = ?", name).First(&m).Error
	return m, err
}

func (d *ResourceDAO) ListAllMenus(ctx context.Context) ([]Menu, error) {
	var menus []Menu
	err := d.getDB(ctx).Where("status = ?", MenuStatusActive).Order("sort ASC").Find(&menus).Error
	return menus, err
}

func (d *ResourceDAO) ListMenusByNames(ctx context.Context, names []string) ([]Menu, error) {
	var menus []Menu
	err := d.getDB(ctx).Where("name IN ?", names).Where("status = ?", MenuStatusActive).Order("sort ASC").Find(&menus).Error
	return menus, err
}

func (d *ResourceDAO) ListMenusByParentID(ctx context.Context, parentID int64) ([]Menu, error) {
	var menus []Menu
	err := d.getDB(ctx).Where("parent_id = ?", parentID).Where("status = ?", MenuStatusActive).Order("sort ASC").Find(&menus).Error
	return menus, err
}

func (d *ResourceDAO) UpdateMenuSort(ctx context.Context, id int64, parentID int64, sort int64) error {
	return d.getDB(ctx).Model(&Menu{}).Where("id = ?", id).Updates(map[string]interface{}{
		"parent_id": parentID,
		"sort":      sort,
		"utime":     time.Now().UnixMilli(),
	}).Error
}

func (d *ResourceDAO) BatchUpdateMenuSort(ctx context.Context, menus []Menu) error {
	if len(menus) == 0 {
		return nil
	}

	now := time.Now().UnixMilli()
	for i := range menus {
		menus[i].Utime = now
	}

	return d.getDB(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"parent_id", "sort", "utime"}),
	}).Create(&menus).Error
}

func (d *ResourceDAO) BatchUpsertMenus(ctx context.Context, menus []Menu) error {
	if len(menus) == 0 {
		return nil
	}

	now := time.Now().UnixMilli()
	for i := range menus {
		if menus[i].Ctime == 0 {
			menus[i].Ctime = now
		}
		menus[i].Utime = now
		menus[i].Status = MenuStatusActive
	}

	return d.getDB(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"parent_id", "path", "component", "redirect", "permission_code", "sort", "meta", "utime", "status"}),
	}).Create(&menus).Error
}

func (d *ResourceDAO) MarkMenusAsOrphan(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}
	return d.getDB(ctx).Model(&Menu{}).
		Where("name NOT IN ?", names).
		Update("status", MenuStatusOrphan).Error
}

func (d *ResourceDAO) InsertAPI(ctx context.Context, a API) (int64, error) {
	now := time.Now().UnixMilli()
	a.Ctime = now
	a.Utime = now
	err := d.getDB(ctx).Create(&a).Error
	return a.Id, err
}

func (d *ResourceDAO) BatchInsertAPI(ctx context.Context, apis []API) error {
	if len(apis) == 0 {
		return nil
	}

	now := time.Now().UnixMilli()
	for i := range apis {
		apis[i].Ctime = now
		apis[i].Utime = now
		apis[i].Status = APIStatusActive
	}

	return d.getDB(ctx).Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns([]string{"name", "utime", "status"}),
	}).Create(&apis).Error
}

func (d *ResourceDAO) FindAPIByPath(ctx context.Context, service, method, path string) (API, error) {
	var a API
	err := d.getDB(ctx).Where("service = ? AND method = ? AND path = ? AND status = ?",
		service, method, path, APIStatusActive).First(&a).Error
	return a, err
}

func (d *ResourceDAO) ListAllAPIs(ctx context.Context) ([]API, error) {
	var apis []API
	err := d.getDB(ctx).Where("status = ?", APIStatusActive).Find(&apis).Error
	return apis, err
}

func (d *ResourceDAO) ListAPIsByService(ctx context.Context, service string) ([]API, error) {
	var apis []API
	err := d.getDB(ctx).Where("service = ?", service).Where("status = ?", APIStatusActive).Find(&apis).Error
	return apis, err
}

func (d *ResourceDAO) DeleteAPIsByServiceAndURNs(ctx context.Context, service string, urns []string) error {
	if len(urns) == 0 {
		return d.getDB(ctx).Where("service = ?", service).Delete(&API{}).Error
	}

	// 利用 MySQL 的 LOWER(CONCAT(method, ':', path)) 来匹配 URN 格式
	return d.getDB(ctx).Where("service = ?", service).
		Where("LOWER(CONCAT(method, ':', path)) NOT IN ?", urns).
		Delete(&API{}).Error
}

func (d *ResourceDAO) MarkAPIsAsOrphan(ctx context.Context, service string, urns []string) error {
	if len(urns) == 0 {
		return d.getDB(ctx).Model(&API{}).Where("service = ?", service).Update("status", APIStatusOrphan).Error
	}

	return d.getDB(ctx).Model(&API{}).Where("service = ?", service).
		Where("LOWER(CONCAT(method, ':', path)) NOT IN ?", urns).
		Update("status", APIStatusOrphan).Error
}

func (d *ResourceDAO) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		newCtx := context.WithValue(ctx, resTxKey{}, tx)
		return fn(newCtx)
	})
}
