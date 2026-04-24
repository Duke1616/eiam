package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
)

// IdentitySource 身份源持久化模型
type IdentitySource struct {
	ID         int64                              `gorm:"primaryKey;autoIncrement"`
	TenantID   int64                              `gorm:"index;comment:'租户ID'"`
	Name       string                             `gorm:"type:varchar(128);NOT NULL;comment:'身份源名称'"`
	Type       string                             `gorm:"type:varchar(32);NOT NULL;index;comment:'身份源类型'"`
	LDAPConfig sqlx.JSONColumn[domain.LDAPConfig] `gorm:"type:json;comment:'LDAP 配置信息'"`
	Enabled    bool                               `gorm:"type:tinyint(1);NOT NULL;default:0;comment:'是否启用'"`
	Ctime      int64                              `gorm:"comment:'创建时间'"`
	Utime      int64                              `gorm:"comment:'更新时间'"`
}

// IIdentitySourceDAO 身份源数据持久化接口
type IIdentitySourceDAO interface {
	// Save 保存或更新身份源配置
	Save(ctx context.Context, source IdentitySource) (int64, error)
	// List 获取当前租户下的身份源列表
	List(ctx context.Context) ([]IdentitySource, error)
	// GetByID 根据 ID 获取身份源详情
	GetByID(ctx context.Context, id int64) (IdentitySource, error)
	// Delete 删除身份源
	Delete(ctx context.Context, id int64) error
}

type identitySourceDAO struct {
	db *gorm.DB
}

func NewIdentitySourceDAO(db *gorm.DB) IIdentitySourceDAO {
	return &identitySourceDAO{db: db}
}

func (dao *identitySourceDAO) Save(ctx context.Context, source IdentitySource) (int64, error) {
	now := time.Now().UnixMilli()
	source.Utime = now
	if source.ID == 0 {
		source.Ctime = now
	}

	// 插件会自动从 context 中提取 tenant_id 并注入
	err := dao.db.WithContext(ctx).Save(&source).Error
	return source.ID, err
}

func (dao *identitySourceDAO) List(ctx context.Context) ([]IdentitySource, error) {
	var res []IdentitySource
	// 即使这里不写 Where("tenant_id = ?")，插件也会自动补全
	err := dao.db.WithContext(ctx).Find(&res).Error
	return res, err
}

func (dao *identitySourceDAO) GetByID(ctx context.Context, id int64) (IdentitySource, error) {
	var res IdentitySource
	err := dao.db.WithContext(ctx).Where("id = ?", id).First(&res).Error
	return res, err
}

func (dao *identitySourceDAO) Delete(ctx context.Context, id int64) error {
	return dao.db.WithContext(ctx).Where("id = ?", id).Delete(&IdentitySource{}).Error
}
