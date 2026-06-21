package dao

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// ITenantKeyDAO 租户密钥数据库持久化接口：负责与底层物理表 tenant_key 进行数据通信
type ITenantKeyDAO interface {
	// Create 新增一条凭证记录，并自动填充创建时间和更新时间
	Create(ctx context.Context, tk TenantKey) (int64, error)
	// FindByAccessKey 精确检索 AccessKey 对应的数据库凭证实体
	FindByAccessKey(ctx context.Context, ak string) (TenantKey, error)
	// ListByTenantID 检索指定租户 ID 拥有的所有密钥实体
	ListByTenantID(ctx context.Context, tenantID int64) ([]TenantKey, error)
	// UpdateStatus 修改指定 ID 凭证的启用/禁用状态，并同步更新修改时间
	UpdateStatus(ctx context.Context, id int64, status int) error
}

type TenantKeyDAO struct {
	db *gorm.DB
}

func NewTenantKeyDAO(db *gorm.DB) ITenantKeyDAO {
	return &TenantKeyDAO{db: db}
}

type TenantKey struct {
	ID          int64  `gorm:"primaryKey;autoIncrement"`
	TenantID    int64  `gorm:"index;column:tenant_id" eiam:"ignore"`
	AccessKey   string `gorm:"uniqueIndex;column:access_key;type:varchar(64)"`
	SecretKey   string `gorm:"column:secret_key;type:varchar(128)"`
	Status      int    `gorm:"column:status;type:tinyint;default:1"`
	Description string `gorm:"column:description;type:varchar(255);default:''"`
	Ctime       int64  `gorm:"column:ctime"`
	Utime       int64  `gorm:"column:utime"`
}

func (TenantKey) TableName() string {
	return "tenant_key"
}

func (d *TenantKeyDAO) Create(ctx context.Context, tk TenantKey) (int64, error) {
	now := time.Now().UnixMilli()
	tk.Ctime = now
	tk.Utime = now
	err := d.db.WithContext(ctx).Create(&tk).Error
	return tk.ID, err
}

func (d *TenantKeyDAO) FindByAccessKey(ctx context.Context, ak string) (TenantKey, error) {
	var tk TenantKey
	err := d.db.WithContext(ctx).Where("access_key = ?", ak).First(&tk).Error
	return tk, err
}

func (d *TenantKeyDAO) ListByTenantID(ctx context.Context, tenantID int64) ([]TenantKey, error) {
	var tks []TenantKey
	err := d.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&tks).Error
	return tks, err
}

func (d *TenantKeyDAO) UpdateStatus(ctx context.Context, id int64, status int) error {
	return d.db.WithContext(ctx).Model(&TenantKey{}).Where("id = ?", id).Updates(map[string]any{
		"status": status,
		"utime":  time.Now().UnixMilli(),
	}).Error
}
