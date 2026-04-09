package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Menu 菜单资源表 (物理元数据)
type Menu struct {
	Id             int64                     `gorm:"type:bigint;primaryKey;autoIncrement;comment:'菜单ID'"`
	ParentId       int64                     `gorm:"type:bigint;not null;default:0;index:idx_parent_id;comment:'父菜单ID'"`
	Name           string                    `gorm:"type:varchar(255);not null;uniqueIndex:uni_name;comment:'名称'"`
	Path           string                    `gorm:"type:varchar(255);comment:'前端路由地址'"`
	Component      string                    `gorm:"type:varchar(255);comment:'前端组件地址'"`
	Redirect       string                    `gorm:"type:varchar(255);comment:'重定向地址'"`
	PermissionCode string                    `gorm:"type:varchar(128);comment:'资源关联的权限码声明'"`
	Sort           int64                     `gorm:"type:bigint;not null;default:0;comment:'排序号'"`
	Meta           sqlx.JSONColumn[MenuMeta] `gorm:"type:json;comment:'展示元数据'"`
	Ctime          int64                     `gorm:"type:bigint;not null;comment:'创建时间'"`
	Utime          int64                     `gorm:"type:bigint;not null;comment:'更新时间'"`
}

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
}

// IResourceDAO 定义了物理资产 (Menu/API) 项目的底层持久化接口
type IResourceDAO interface {
	InsertMenu(ctx context.Context, m Menu) (int64, error)
	UpdateMenu(ctx context.Context, m Menu) error
	FindMenuByName(ctx context.Context, name string) (Menu, error)
	ListAllMenus(ctx context.Context) ([]Menu, error)
	ListMenusByParentID(ctx context.Context, parentID int64) ([]Menu, error)

	UpdateMenuSort(ctx context.Context, id int64, parentID int64, sort int64) error
	BatchUpdateMenuSort(ctx context.Context, menus []Menu) error
	// DeleteMenusByNames 删除不在指定名称列表中的所有菜单
	DeleteMenusByNames(ctx context.Context, names []string) error
	// BatchInsertMenus 批量插入或更新菜单
	BatchUpsertMenus(ctx context.Context, menus []Menu) error

	InsertAPI(ctx context.Context, a API) (int64, error)
	BatchInsertAPI(ctx context.Context, apis []API) error
	ListAllAPIs(ctx context.Context) ([]API, error)
	ListAPIsByService(ctx context.Context, service string) ([]API, error)

	// Transaction 开启事务支持
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}

type ResourceDAO struct {
	db *gorm.DB
}

type txKey struct{}

func (d *ResourceDAO) getDB(ctx context.Context) *gorm.DB {
	tx, ok := ctx.Value(txKey{}).(*gorm.DB)
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
	err := d.getDB(ctx).Order("sort ASC").Find(&menus).Error
	return menus, err
}

func (d *ResourceDAO) ListMenusByParentID(ctx context.Context, parentID int64) ([]Menu, error) {
	var menus []Menu
	err := d.getDB(ctx).Where("parent_id = ?", parentID).Order("sort ASC").Find(&menus).Error
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
		menus[i].Ctime = now
		menus[i].Utime = now
	}

	return d.getDB(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"parent_id", "path", "component", "redirect", "permission_code", "sort", "meta", "utime"}),
	}).Create(&menus).Error
}

func (d *ResourceDAO) DeleteMenusByNames(ctx context.Context, names []string) error {
	if len(names) == 0 {
		// 如果 YAML 为空，理论上要删全量，但为了安全，如果 names 为空通常不操作或显式传空。
		// 在这里我们假定 Full Sync 需要传入所有合法的 Name。
		return d.getDB(ctx).Where("1=1").Delete(&Menu{}).Error
	}
	return d.getDB(ctx).Where("name NOT IN ?", names).Delete(&Menu{}).Error
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
	}

	return d.getDB(ctx).Clauses(clause.OnConflict{
		DoUpdates: clause.AssignmentColumns([]string{"name", "utime"}),
	}).Create(&apis).Error
}

func (d *ResourceDAO) ListAllAPIs(ctx context.Context) ([]API, error) {
	var apis []API
	err := d.getDB(ctx).Find(&apis).Error
	return apis, err
}

func (d *ResourceDAO) ListAPIsByService(ctx context.Context, service string) ([]API, error) {
	var apis []API
	err := d.getDB(ctx).Where("service = ?", service).Find(&apis).Error
	return apis, err
}

func (d *ResourceDAO) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		newCtx := context.WithValue(ctx, txKey{}, tx)
		return fn(newCtx)
	})
}
