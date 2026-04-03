package dao

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// Permission 逻辑权限能力定义 (全平台标准，不分租户)
type Permission struct {
	Id     int64  `gorm:"type:bigint;primaryKey;autoIncrement;comment:'权限ID'"`
	Code   string `gorm:"type:varchar(128);not null;uniqueIndex:uniq_idx_perm_code;comment:'逻辑权限码'"`
	Name   string `gorm:"type:varchar(255);not null;comment:'能力名称'"`
	Desc   string `gorm:"type:varchar(512);not null;default:'';comment:'功能描述'"`
	Group  string `gorm:"type:varchar(64);not null;default:'';comment:'所属分组'"`
	Status int32  `gorm:"type:tinyint;not null;default:1;comment:'1-启用, 0-禁用'"`
	Ctime  int64  `gorm:"type:bigint;not null;comment:'创建时间'"`
	Utime  int64  `gorm:"type:bigint;not null;comment:'更新时间'"`
}

// PermissionBinding 物理资产关联表 (全局通用映射)
// 决定了 "iam:user:view" 这个 Code 映射了哪些 API 或 菜单
type PermissionBinding struct {
	Id           int64  `gorm:"type:bigint;primaryKey;autoIncrement;comment:'映射ID'"`
	PermId       int64  `gorm:"type:bigint;not null;index:idx_perm_id;comment:'权限能力ID'"`
	PermCode     string `gorm:"type:varchar(128);not null;index:idx_perm_code;comment:'权限能力码'"`
	ResourceType string `gorm:"type:varchar(32);not null;index:idx_res;comment:'资源类型: menu/api'"`
	ResourceId   int64  `gorm:"type:bigint;not null;index:idx_res;comment:'具体资产ID'"`
}

type IPermissionDAO interface {
	Insert(ctx context.Context, p Permission) (int64, error)
	Delete(ctx context.Context, id int64) error
	GetByCode(ctx context.Context, code string) (Permission, error)

	// BindResources 批量关联物理资产
	BindResources(ctx context.Context, bindings []PermissionBinding) error
	// GetBindingsByRes 反查：查看 API/Menu 归属哪些能力码
	GetBindingsByRes(ctx context.Context, resType string, resId int64) ([]PermissionBinding, error)
	// ListBindingsByPerm 正查：查看能力项下的全部资产
	ListBindingsByPerm(ctx context.Context, permId int64) ([]PermissionBinding, error)
}

type PermissionDAO struct {
	db *gorm.DB
}

func NewPermissionDAO(db *gorm.DB) IPermissionDAO {
	return &PermissionDAO{db: db}
}

func (d *PermissionDAO) Insert(ctx context.Context, p Permission) (int64, error) {
	now := time.Now().UnixMilli()
	p.Ctime = now
	p.Utime = now
	err := d.db.WithContext(ctx).Create(&p).Error
	return p.Id, err
}

func (d *PermissionDAO) Delete(ctx context.Context, id int64) error {
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", id).Delete(&Permission{}).Error; err != nil {
			return err
		}
		return tx.Where("perm_id = ?", id).Delete(&PermissionBinding{}).Error
	})
}

func (d *PermissionDAO) GetByCode(ctx context.Context, code string) (Permission, error) {
	var p Permission
	err := d.db.WithContext(ctx).Where("code = ?", code).First(&p).Error
	return p, err
}

func (d *PermissionDAO) BindResources(ctx context.Context, bindings []PermissionBinding) error {
	return d.db.WithContext(ctx).Create(&bindings).Error
}

func (d *PermissionDAO) GetBindingsByRes(ctx context.Context, resType string, resId int64) ([]PermissionBinding, error) {
	var res []PermissionBinding
	err := d.db.WithContext(ctx).Where("resource_type = ? AND resource_id = ?", resType, resId).Find(&res).Error
	return res, err
}

func (d *PermissionDAO) ListBindingsByPerm(ctx context.Context, permId int64) ([]PermissionBinding, error) {
	var res []PermissionBinding
	err := d.db.WithContext(ctx).Where("perm_id = ?", permId).Find(&res).Error
	return res, err
}
