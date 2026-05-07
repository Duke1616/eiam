package dao

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/samber/lo"
	"gorm.io/gorm"
)

// IdentitySource 身份源持久化模型
type IdentitySource struct {
	ID            int64                                 `gorm:"primaryKey;autoIncrement"`
	Name          string                                `gorm:"type:varchar(128);NOT NULL;comment:'身份源名称'"`
	Type          string                                `gorm:"type:varchar(32);NOT NULL;index;comment:'身份源类型'"`
	LDAPConfig    sqlx.JSONColumn[domain.LDAPConfig]    `gorm:"type:json;column:ldap_config;comment:'LDAP 配置信息'"`
	OIDCConfig    sqlx.JSONColumn[domain.OIDCConfig]    `gorm:"type:json;column:oidc_config;comment:'OIDC 配置信息'"`
	LocalConfig   sqlx.JSONColumn[domain.LocalConfig]   `gorm:"type:json;column:local_config;comment:'本地口令策略'"`
	PasskeyConfig sqlx.JSONColumn[domain.PasskeyConfig] `gorm:"type:json;column:passkey_config;comment:'Passkey 配置信息'"`
	Enabled       bool                                  `gorm:"type:tinyint(1);NOT NULL;default:0;comment:'是否启用'"`
	Ctime         int64                                 `gorm:"comment:'创建时间'"`
	Utime         int64                                 `gorm:"comment:'更新时间'"`
}

// IIdentitySourceDAO 身份源数据持久化接口
type IIdentitySourceDAO interface {
	// Save 保存或更新身份源配置
	Save(ctx context.Context, source IdentitySource) (int64, error)
	// List 获取身份源列表
	List(ctx context.Context) ([]IdentitySource, error)
	// GetByID 根据 ID 获取身份源详情
	GetByID(ctx context.Context, id int64) (IdentitySource, error)
	// GetEnabledByType 获取指定类型且已启用的身份源列表
	GetEnabledByType(ctx context.Context, sourceType string) ([]IdentitySource, error)
	// GetEnabled 获取所有已启用的身份源列表
	GetEnabled(ctx context.Context) ([]IdentitySource, error)
	// Delete 删除身份源
	Delete(ctx context.Context, id int64) error
	// ToggleEnabled 切换身份源启用状态（取反）
	ToggleEnabled(ctx context.Context, id int64) error
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
		err := dao.db.WithContext(ctx).Create(&source).Error
		return source.ID, err
	}

	// 更新逻辑：利用 MySQL JSON_MERGE_PATCH 实现局部更新，避免先查后改
	updates := map[string]interface{}{
		"name":    source.Name,
		"enabled": source.Enabled,
		"utime":   now,
	}

	// 处理不同类型的配置增量更新
	if source.LDAPConfig.Valid {
		updates["ldap_config"] = gorm.Expr("JSON_MERGE_PATCH(ldap_config, ?)", dao.toPatch(source.LDAPConfig.Val))
	}
	if source.OIDCConfig.Valid {
		updates["oidc_config"] = gorm.Expr("JSON_MERGE_PATCH(oidc_config, ?)", dao.toPatch(source.OIDCConfig.Val))
	}
	if source.LocalConfig.Valid {
		updates["local_config"] = gorm.Expr("JSON_MERGE_PATCH(local_config, ?)", dao.toPatch(source.LocalConfig.Val))
	}
	if source.PasskeyConfig.Valid {
		updates["passkey_config"] = gorm.Expr("JSON_MERGE_PATCH(passkey_config, ?)", dao.toPatch(source.PasskeyConfig.Val))
	}

	err := dao.db.WithContext(ctx).Model(&IdentitySource{ID: source.ID}).Updates(updates).Error
	return source.ID, err
}

func (dao *identitySourceDAO) toPatch(val any) string {
	// 通过 Marshal/Unmarshal 将结构体转为 map，确保遵循 JSON Tag 定义
	bs, _ := json.Marshal(val)
	var m map[string]any
	_ = json.Unmarshal(bs, &m)

	// 剔除空值或占位符，以便 JSON_MERGE_PATCH 保留数据库原值
	cleaned := lo.OmitBy(m, func(_ string, v any) bool {
		s, ok := v.(string)
		return ok && (s == "" || s == "******")
	})

	res, _ := json.Marshal(cleaned)
	return string(res)
}

func (dao *identitySourceDAO) List(ctx context.Context) ([]IdentitySource, error) {
	var res []IdentitySource
	err := dao.db.WithContext(ctx).Find(&res).Error
	return res, err
}

func (dao *identitySourceDAO) GetByID(ctx context.Context, id int64) (IdentitySource, error) {
	var res IdentitySource
	err := dao.db.WithContext(ctx).Where("id = ?", id).First(&res).Error
	return res, err
}

func (dao *identitySourceDAO) GetEnabledByType(ctx context.Context, sourceType string) ([]IdentitySource, error) {
	var res []IdentitySource
	err := dao.db.WithContext(ctx).
		Where("type = ? AND enabled = ?", sourceType, true).
		Find(&res).Error
	return res, err
}

func (dao *identitySourceDAO) GetEnabled(ctx context.Context) ([]IdentitySource, error) {
	var res []IdentitySource
	err := dao.db.WithContext(ctx).
		Where("enabled = ?", true).
		Find(&res).Error
	return res, err
}

func (dao *identitySourceDAO) Delete(ctx context.Context, id int64) error {
	return dao.db.WithContext(ctx).Where("id = ?", id).Delete(&IdentitySource{}).Error
}

func (dao *identitySourceDAO) ToggleEnabled(ctx context.Context, id int64) error {
	return dao.db.WithContext(ctx).Model(&IdentitySource{}).Where("id = ?", id).
		Updates(map[string]interface{}{
			"enabled": gorm.Expr("NOT enabled"),
			"utime":   time.Now().UnixMilli(),
		}).Error
}
