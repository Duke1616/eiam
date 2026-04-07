package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
)

// Menu 菜单资源表 (物理元数据)
type Menu struct {
	Id             int64                     `gorm:"type:bigint;primaryKey;autoIncrement;comment:'菜单ID'"`
	ParentId       int64                     `gorm:"type:bigint;not null;default:0;index:idx_parent_id;comment:'父菜单ID'"`
	Name           string                    `gorm:"type:varchar(255);not null;comment:'名称'"`
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

	InsertAPI(ctx context.Context, a API) (int64, error)
	ListAllAPIs(ctx context.Context) ([]API, error)
}

type ResourceDAO struct {
	db *gorm.DB
}

func NewResourceDAO(db *gorm.DB) IResourceDAO {
	return &ResourceDAO{db: db}
}

func (d *ResourceDAO) InsertMenu(ctx context.Context, m Menu) (int64, error) {
	now := time.Now().UnixMilli()
	m.Ctime = now
	m.Utime = now
	err := d.db.WithContext(ctx).Create(&m).Error
	return m.Id, err
}

func (d *ResourceDAO) UpdateMenu(ctx context.Context, m Menu) error {
	return d.db.WithContext(ctx).Model(&Menu{}).Where("id = ?", m.Id).Updates(map[string]interface{}{
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
	err := d.db.WithContext(ctx).Where("name = ?", name).First(&m).Error
	return m, err
}

func (d *ResourceDAO) ListAllMenus(ctx context.Context) ([]Menu, error) {
	var menus []Menu
	err := d.db.WithContext(ctx).Order("sort ASC").Find(&menus).Error
	return menus, err
}

func (d *ResourceDAO) ListMenusByParentID(ctx context.Context, parentID int64) ([]Menu, error) {
	var menus []Menu
	err := d.db.WithContext(ctx).Where("parent_id = ?", parentID).Order("sort ASC").Find(&menus).Error
	return menus, err
}

func (d *ResourceDAO) UpdateMenuSort(ctx context.Context, id int64, parentID int64, sort int64) error {
	return d.db.WithContext(ctx).Model(&Menu{}).Where("id = ?", id).Updates(map[string]interface{}{
		"parent_id": parentID,
		"sort":      sort,
		"utime":     time.Now().UnixMilli(),
	}).Error
}

func (d *ResourceDAO) BatchUpdateMenuSort(ctx context.Context, menus []Menu) error {
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, m := range menus {
			if err := tx.Model(&Menu{}).Where("id = ?", m.Id).Updates(map[string]interface{}{
				"parent_id": m.ParentId,
				"sort":      m.Sort,
				"utime":     time.Now().UnixMilli(),
			}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *ResourceDAO) InsertAPI(ctx context.Context, a API) (int64, error) {
	now := time.Now().UnixMilli()
	a.Ctime = now
	a.Utime = now
	err := d.db.WithContext(ctx).Create(&a).Error
	return a.Id, err
}

func (d *ResourceDAO) ListAllAPIs(ctx context.Context) ([]API, error) {
	var apis []API
	err := d.db.WithContext(ctx).Find(&apis).Error
	return apis, err
}
