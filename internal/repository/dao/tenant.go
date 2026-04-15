package dao

import (
	"context"

	"gorm.io/gorm"
)

// ITenantDAO 租户数据持久化接口
type ITenantDAO interface {
	Create(ctx context.Context, t Tenant) (int64, error)
	FindById(ctx context.Context, id int64) (Tenant, error)
	FindByCode(ctx context.Context, code string) (Tenant, error)
	FindAll(ctx context.Context) ([]Tenant, error)

	// --- Membership 持久化 ---

	InsertMembership(ctx context.Context, m Membership) error
	GetMembership(ctx context.Context, tenantId, userId int64) (Membership, error)

	GetMembershipByUserId(ctx context.Context, userId int64) (Membership, error)
	FindMembershipsByUserIds(ctx context.Context, userIds []int64) ([]Membership, error)
	FindTenantIDsByUserId(ctx context.Context, userId int64) ([]int64, error)
	FindTenantsByIDs(ctx context.Context, ids []int64) ([]Tenant, error)
}

type TenantDAO struct {
	db *gorm.DB
}

func NewTenantDAO(db *gorm.DB) ITenantDAO {
	return &TenantDAO{db: db}
}

type Tenant struct {
	ID     int64  `gorm:"primaryKey;autoIncrement"`
	Name   string `gorm:"type:varchar(255)"`
	Code   string `gorm:"uniqueIndex;type:varchar(64)"`
	Domain string `gorm:"type:varchar(255)"`
	Status int    `gorm:"type:tinyint"`
	Ctime  int64  `gorm:"comment:'创建时间'"`
	Utime  int64  `gorm:"comment:'更新时间'"`
}

// Membership 映射表：仅代表入驻契约，不存储动态授权。
type Membership struct {
	ID       int64 `gorm:"primaryKey;autoIncrement"`
	TenantID int64 `gorm:"index:idx_tenant_user"`
	UserID   int64 `gorm:"index:idx_tenant_user"`
	Ctime    int64 `gorm:"comment:'创建时间'"`
}

func (m Membership) TableName() string {
	return "membership"
}

func (d *TenantDAO) Create(ctx context.Context, t Tenant) (int64, error) {
	err := d.db.WithContext(ctx).Create(&t).Error
	return t.ID, err
}

func (d *TenantDAO) InsertMembership(ctx context.Context, m Membership) error {
	return d.db.WithContext(ctx).Create(&m).Error
}

func (d *TenantDAO) GetMembership(ctx context.Context, tenantId, userId int64) (Membership, error) {
	var m Membership
	err := d.db.WithContext(ctx).Where("tenant_id = ? AND user_id = ?", tenantId, userId).First(&m).Error
	return m, err
}

func (d *TenantDAO) GetMembershipByUserId(ctx context.Context, userId int64) (Membership, error) {
	var m Membership
	// 注意：此处不显式传 tenant_id，交给 GORM 拦截器全权处理
	err := d.db.WithContext(ctx).Where("user_id = ?", userId).First(&m).Error
	return m, err
}

func (d *TenantDAO) FindMembershipsByUserIds(ctx context.Context, userIds []int64) ([]Membership, error) {
	var ms []Membership
	if len(userIds) == 0 {
		return ms, nil
	}
	err := d.db.WithContext(ctx).Where("user_id IN ?", userIds).Find(&ms).Error
	return ms, err
}

func (d *TenantDAO) FindById(ctx context.Context, id int64) (Tenant, error) {
	var t Tenant
	err := d.db.WithContext(ctx).Where("id = ?", id).First(&t).Error
	return t, err
}

func (d *TenantDAO) FindByCode(ctx context.Context, code string) (Tenant, error) {
	var t Tenant
	err := d.db.WithContext(ctx).Where("code = ?", code).First(&t).Error
	return t, err
}

func (d *TenantDAO) FindAll(ctx context.Context) ([]Tenant, error) {
	var ts []Tenant
	err := d.db.WithContext(ctx).Find(&ts).Error
	return ts, err
}

// FindTenantIDsByUserId 查询用户入驻的所有租户 ID（走 membership 索引）
func (d *TenantDAO) FindTenantIDsByUserId(ctx context.Context, userId int64) ([]int64, error) {
	var ms []Membership
	err := d.db.WithContext(ctx).Select("tenant_id").Where("user_id = ?", userId).Find(&ms).Error
	if err != nil {
		return nil, err
	}

	ids := make([]int64, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.TenantID)
	}
	return ids, nil
}

// FindTenantsByIDs 按 ID 列表批量查租户信息
func (d *TenantDAO) FindTenantsByIDs(ctx context.Context, ids []int64) ([]Tenant, error) {
	var ts []Tenant
	err := d.db.WithContext(ctx).Where("id IN ?", ids).Find(&ts).Error
	return ts, err
}
