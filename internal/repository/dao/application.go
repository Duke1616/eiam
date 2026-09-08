package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/pkg/gormx"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
)

// Application 下游接入应用 GORM 持久化模型
type Application struct {
	ID               int64                     `gorm:"primaryKey;autoIncrement"`
	TenantID         int64                     `gorm:"column:tenant_id;type:bigint;index;NOT NULL;comment:'归属租户ID'" eiam:"shared"`
	Protocol         string                    `gorm:"column:protocol;type:varchar(32);NOT NULL;default:'oidc';comment:'接入协议类型: oidc, cas, saml'"`
	ClientID         string                    `gorm:"column:client_id;type:varchar(64);uniqueIndex;NOT NULL;comment:'应用唯一客户端标识'"`
	ClientSecretHash string                    `gorm:"column:client_secret_hash;type:varchar(255);NOT NULL;default:'';comment:'客户端密钥哈希'"`
	Name             string                    `gorm:"column:name;type:varchar(128);NOT NULL;comment:'应用名称'"`
	Logo             string                    `gorm:"column:logo;type:varchar(255);default:'';comment:'应用图标URL'"`
	RedirectURIs     sqlx.JSONColumn[[]string] `gorm:"column:redirect_uris;type:json;comment:'合法重定向白名单'"`
	ResponseTypes    sqlx.JSONColumn[[]string] `gorm:"column:response_types;type:json;comment:'允许的响应类型'"`
	GrantTypes       sqlx.JSONColumn[[]string] `gorm:"column:grant_types;type:json;comment:'允许的授权模式'"`
	Scopes           sqlx.JSONColumn[[]string] `gorm:"column:scopes;type:json;comment:'允许申请的权限范围'"`
	IsPublic         bool                      `gorm:"column:is_public;type:tinyint(1);NOT NULL;default:0;comment:'是否为公共客户端'"`
	AutoConsent      bool                      `gorm:"column:auto_consent;type:tinyint(1);NOT NULL;default:1;comment:'是否跳过授权确认'"`
	Ctime            int64                     `gorm:"column:ctime;comment:'创建时间戳'"`
	Utime            int64                     `gorm:"column:utime;comment:'更新时间戳'"`
}

// TableName 指定 Application 对应的数据库表名
func (Application) TableName() string {
	return "application"
}

// IApplicationDAO 下游接入应用数据持久化接口
type IApplicationDAO interface {
	// Create 创建接入应用
	Create(ctx context.Context, app Application) (int64, error)
	// Update 更新应用基础信息及白名单
	Update(ctx context.Context, app Application) error
	// UpdateSecret 更新应用密钥哈希
	UpdateSecret(ctx context.Context, id int64, secretHash string) error
	// FindByID 根据主键获取应用
	FindByID(ctx context.Context, id int64) (Application, error)
	// FindByClientID 根据 client_id 获取应用 (跨租户全局匹配应用)
	FindByClientID(ctx context.Context, clientID string) (Application, error)
	// ListByTenantID 获取指定租户下的所有应用
	ListByTenantID(ctx context.Context, tenantID int64, offset, limit int) ([]Application, int64, error)
	// Delete 删除指定应用
	Delete(ctx context.Context, id int64) error
}

type applicationDAO struct {
	db *gorm.DB
}

// NewApplicationDAO 构造应用持久化 DAO 实例
func NewApplicationDAO(db *gorm.DB) IApplicationDAO {
	return &applicationDAO{db: db}
}

func (dao *applicationDAO) Create(ctx context.Context, app Application) (int64, error) {
	now := time.Now().UnixMilli()
	app.Ctime = now
	app.Utime = now
	err := dao.db.WithContext(ctx).Create(&app).Error
	return app.ID, err
}

func (dao *applicationDAO) Update(ctx context.Context, app Application) error {
	now := time.Now().UnixMilli()
	return dao.db.WithContext(ctx).Model(&Application{}).
		Where("id = ?", app.ID).
		Updates(map[string]any{
			"name":           app.Name,
			"logo":           app.Logo,
			"redirect_uris":  app.RedirectURIs,
			"response_types": app.ResponseTypes,
			"grant_types":    app.GrantTypes,
			"scopes":         app.Scopes,
			"is_public":      app.IsPublic,
			"auto_consent":   app.AutoConsent,
			"utime":          now,
		}).Error
}

func (dao *applicationDAO) UpdateSecret(ctx context.Context, id int64, secretHash string) error {
	now := time.Now().UnixMilli()
	return dao.db.WithContext(ctx).Model(&Application{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"client_secret_hash": secretHash,
			"utime":              now,
		}).Error
}

func (dao *applicationDAO) FindByID(ctx context.Context, id int64) (Application, error) {
	var app Application
	err := dao.db.WithContext(ctx).Where("id = ?", id).First(&app).Error
	return app, err
}

func (dao *applicationDAO) FindByClientID(ctx context.Context, clientID string) (Application, error) {
	var app Application
	// client_id 是全局唯一索引键，OIDC/CAS/SAML 跨租户核心匹配查询，在此处使用 Scope 局域提权
	err := dao.db.WithContext(ctx).
		Scopes(gormx.IgnoreTenant()).
		Where("client_id = ?", clientID).
		First(&app).Error
	return app, err
}

func (dao *applicationDAO) ListByTenantID(ctx context.Context, tenantID int64, offset, limit int) ([]Application, int64, error) {
	var apps []Application
	var total int64
	query := dao.db.WithContext(ctx).Model(&Application{}).Where("tenant_id = ?", tenantID)
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	err := query.Order("id DESC").Offset(offset).Limit(limit).Find(&apps).Error
	return apps, total, err
}

func (dao *applicationDAO) Delete(ctx context.Context, id int64) error {
	return dao.db.WithContext(ctx).Where("id = ?", id).Delete(&Application{}).Error
}
