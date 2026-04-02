package dao

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// Tenant 租户表
type Tenant struct {
	Id      int64  `gorm:"primaryKey;autoIncrement"`
	Name    string `gorm:"size:128;not null"`
	Code    string `gorm:"size:64;uniqueIndex;not null"`
	Type    int8   `gorm:"index;not null"`
	OwnerId int64  `gorm:"index;not null"`
	Status  int8   `gorm:"index;not null;default:1"`
	Ctime   int64  `gorm:"comment:'创建时间'"`
	Utime   int64  `gorm:"comment:'更新时间'"`
}

// Member 租户成员关系表
type Member struct {
	Id       int64 `gorm:"primaryKey;autoIncrement"`
	TenantId int64 `gorm:"uniqueIndex:idx_tenant_user;not null"`
	UserId   int64 `gorm:"uniqueIndex:idx_tenant_user;not null"`
	Status   int8  `gorm:"index;default:1"`
	Ctime    int64 `gorm:"autoCreateTime"`
	Utime    int64 `gorm:"autoUpdateTime"`
}

// ITenantDAO 租户数据库操作接口
type ITenantDAO interface {
	Insert(ctx context.Context, t Tenant) (int64, error)
	InsertMember(ctx context.Context, m Member) error
	GetById(ctx context.Context, id int64) (Tenant, error)
	GetByUserId(ctx context.Context, userId int64) ([]Tenant, error)
	GetMember(ctx context.Context, tenantId, userId int64) (bool, error)
}

type TenantDAO struct {
	db *gorm.DB
}

func NewTenantDAO(db *gorm.DB) ITenantDAO {
	return &TenantDAO{db: db}
}

func (d *TenantDAO) Insert(ctx context.Context, t Tenant) (int64, error) {
	err := d.db.WithContext(ctx).Create(&t).Error
	return t.Id, err
}

func (d *TenantDAO) InsertMember(ctx context.Context, m Member) error {
	return d.db.WithContext(ctx).Create(&m).Error
}

func (d *TenantDAO) GetById(ctx context.Context, id int64) (Tenant, error) {
	var t Tenant
	err := d.db.WithContext(ctx).First(&t, id).Error
	return t, err
}

func (d *TenantDAO) GetByUserId(ctx context.Context, userId int64) ([]Tenant, error) {
	var ts []Tenant
	// 通过关联查询获取用户所属的所有租户
	// NOTE: GORM 默认表名可能是复数形式（如 tenants / members）
	err := d.db.WithContext(ctx).
		Table("tenant").
		Joins("JOIN member ON member.tenant_id = tenant.id").
		Where("member.user_id = ?", userId).
		Find(&ts).Error
	return ts, err
}

func (d *TenantDAO) GetMember(ctx context.Context, tenantId, userId int64) (bool, error) {
	var m Member
	err := d.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantId, userId).
		First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
