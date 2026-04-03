package dao

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// Menu 菜单资源表 (物理元数据)
type Menu struct {
	Id        int64  `gorm:"type:bigint;primaryKey;autoIncrement;comment:'菜单ID'"`
	ParentId  int64  `gorm:"type:bigint;not null;default:0;index:idx_parent_id;comment:'父菜单ID'"`
	TenantId  int64  `gorm:"type:bigint;not null;default:0;index:idx_tenant_id;comment:'租户ID'"`
	Name      string `gorm:"type:varchar(255);not null;comment:'名称'"`
	Path      string `gorm:"type:varchar(255);comment:'前端路由地址'"`
	Component string `gorm:"type:varchar(255);comment:'前端组件地址'"`
	Icon      string `gorm:"type:varchar(128);comment:'图标'"`
	Sort      int32  `gorm:"type:int;not null;default:0;comment:'排序号'"`
	Hidden    bool   `gorm:"type:tinyint;not null;default:0;comment:'1-隐藏, 0-显示'"`
	Ctime     int64  `gorm:"type:bigint;not null;comment:'创建时间'"`
	Utime     int64  `gorm:"type:bigint;not null;comment:'更新时间'"`
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
	ListMenusByTenant(ctx context.Context, tenantId int64) ([]Menu, error)
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
		"name":      m.Name,
		"path":      m.Path,
		"component": m.Component,
		"icon":      m.Icon,
		"sort":      m.Sort,
		"hidden":    m.Hidden,
		"utime":     time.Now().UnixMilli(),
	}).Error
}

func (d *ResourceDAO) ListMenusByTenant(ctx context.Context, tenantId int64) ([]Menu, error) {
	var menus []Menu
	err := d.db.WithContext(ctx).Where("tenant_id = ?", tenantId).Order("sort ASC").Find(&menus).Error
	return menus, err
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
