package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"gorm.io/gorm"
)

// Permission 逻辑权限项实体 (GORM)
type Permission struct {
	Id       int64  `gorm:"type:bigint;primaryKey;autoIncrement;comment:'权限ID'"`
	TenantId int64  `gorm:"type:bigint;not null;default:0;index:idx_tenant_id;comment:'租户ID'"`
	Code     string `gorm:"type:varchar(128);not null;uniqueIndex:uniq_idx_tenant_perm_code;comment:'逻辑权限码'"`
	Name     string `gorm:"type:varchar(255);not null;comment:'名称'"`
	Desc     string `gorm:"type:varchar(512);not null;default:'';comment:'描述'"`
	Group    string `gorm:"type:varchar(64);not null;default:'';comment:'所属分组'"`
	Status   bool   `gorm:"type:tinyint;not null;default:1;comment:'状态: 1-启用, 0-禁用'"`
	Ctime    int64  `gorm:"type:bigint;not null;comment:'创建时间'"`
	Utime    int64  `gorm:"type:bigint;not null;comment:'更新时间'"`
}

// PermissionBinding 权限与资源的物理映射关系 (GORM)
type PermissionBinding struct {
	Id           int64  `gorm:"type:bigint;primaryKey;autoIncrement;comment:'自增ID'"`
	TenantId     int64  `gorm:"type:bigint;not null;default:0;index:idx_tenant_id;comment:'租户ID'"`
	PermId       int64  `gorm:"type:bigint;not null;index:idx_perm_id;comment:'对应权限ID'"`
	PermCode     string `gorm:"type:varchar(128);not null;index:idx_perm_code;comment:'冗余冗余Code方便反查'"`
	ResourceType string `gorm:"type:varchar(32);not null;comment:'资源颗粒度: API/MENU'"`
	ResourceId   int64  `gorm:"type:bigint;not null;index:idx_resource_id;comment:'物理资源ID'"`
}

// IPermissionDAO 权限项及其资产绑定的底层持久化接口
type IPermissionDAO interface {
	// Insert 创建一条新的逻辑权限记录
	Insert(ctx context.Context, p Permission) (int64, error)
	// Delete 删除权限项并同步清理其所有资产绑定关系
	Delete(ctx context.Context, tenantId int64, id int64) error
	// GetByCode 根据逻辑代码获取权限详情
	GetByCode(ctx context.Context, tenantId int64, code string) (Permission, error)

	// BindResource 批量创建资产绑定关系
	BindResource(ctx context.Context, bindings []PermissionBinding) error
	// UnbindResources 解除指定的资源绑定关系
	UnbindResources(ctx context.Context, permId int64, resType domain.ResourceType, resIds []int64) error
	// ListBindings 查询指定权限点下绑定的所有资产列表
	ListBindings(ctx context.Context, permId int64) ([]PermissionBinding, error)
	// GetBindingsByRes 根据物理资产反查其所属权限
	GetBindingsByRes(ctx context.Context, resType domain.ResourceType, resId int64) ([]PermissionBinding, error)
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

func (d *PermissionDAO) Delete(ctx context.Context, tenantId int64, id int64) error {
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ? AND tenant_id = ?", id, tenantId).Delete(&Permission{}).Error; err != nil {
			return err
		}
		return tx.Where("perm_id = ?", id).Delete(&PermissionBinding{}).Error
	})
}

func (d *PermissionDAO) GetByCode(ctx context.Context, tenantId int64, code string) (Permission, error) {
	var p Permission
	err := d.db.WithContext(ctx).Where("tenant_id = ? AND code = ?", tenantId, code).First(&p).Error
	return p, err
}

func (d *PermissionDAO) BindResource(ctx context.Context, bindings []PermissionBinding) error {
	return d.db.WithContext(ctx).Create(&bindings).Error
}

func (d *PermissionDAO) UnbindResources(ctx context.Context, permId int64, resType domain.ResourceType, resIds []int64) error {
	return d.db.WithContext(ctx).Where("perm_id = ? AND resource_type = ? AND resource_id IN ?", permId, resType, resIds).
		Delete(&PermissionBinding{}).Error
}

func (d *PermissionDAO) ListBindings(ctx context.Context, permId int64) ([]PermissionBinding, error) {
	var bindings []PermissionBinding
	err := d.db.WithContext(ctx).Where("perm_id = ?", permId).Find(&bindings).Error
	return bindings, err
}

func (d *PermissionDAO) GetBindingsByRes(ctx context.Context, resType domain.ResourceType, resId int64) ([]PermissionBinding, error) {
	var bindings []PermissionBinding
	err := d.db.WithContext(ctx).Where("resource_type = ? AND resource_id = ?", resType, resId).Find(&bindings).Error
	return bindings, err
}
