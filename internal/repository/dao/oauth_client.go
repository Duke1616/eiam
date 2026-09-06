package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/pkg/gormx"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
)

// OAuthClient 下游应用 GORM 持久化模型
type OAuthClient struct {
	ID               int64                     `gorm:"primaryKey;autoIncrement"`
	TenantID         int64                     `gorm:"column:tenant_id;type:bigint;index;NOT NULL;comment:'归属租户ID'" eiam:"shared"`
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

// TableName 指定 OAuthClient 对应的数据库表名
func (OAuthClient) TableName() string {
	return "oauth_clients"
}

// IOAuthClientDAO 下游接入应用数据持久化接口
type IOAuthClientDAO interface {
	// Create 创建接入应用
	Create(ctx context.Context, client OAuthClient) (int64, error)
	// Update 更新应用基础信息及白名单
	Update(ctx context.Context, client OAuthClient) error
	// UpdateSecret 更新应用密钥哈希
	UpdateSecret(ctx context.Context, id int64, secretHash string) error
	// FindByID 根据主键获取应用
	FindByID(ctx context.Context, id int64) (OAuthClient, error)
	// FindByClientID 根据 client_id 获取应用 (OIDC 授权核心查询，跨租户匹配 client_id)
	FindByClientID(ctx context.Context, clientID string) (OAuthClient, error)
	// ListByTenantID 获取指定租户下的所有应用
	ListByTenantID(ctx context.Context, tenantID int64, offset, limit int) ([]OAuthClient, int64, error)
	// Delete 删除指定应用
	Delete(ctx context.Context, id int64) error
}

type oauthClientDAO struct {
	db *gorm.DB
}

// NewOAuthClientDAO 构造 OAuth 接入应用 DAO 实例
func NewOAuthClientDAO(db *gorm.DB) IOAuthClientDAO {
	return &oauthClientDAO{db: db}
}

func (dao *oauthClientDAO) Create(ctx context.Context, client OAuthClient) (int64, error) {
	now := time.Now().UnixMilli()
	client.Ctime = now
	client.Utime = now
	err := dao.db.WithContext(ctx).Create(&client).Error
	return client.ID, err
}

func (dao *oauthClientDAO) Update(ctx context.Context, client OAuthClient) error {
	client.Utime = time.Now().UnixMilli()
	return dao.db.WithContext(ctx).Model(&OAuthClient{}).
		Where("id = ?", client.ID).
		Updates(map[string]any{
			"name":           client.Name,
			"logo":           client.Logo,
			"redirect_uris":  client.RedirectURIs,
			"response_types": client.ResponseTypes,
			"grant_types":    client.GrantTypes,
			"scopes":         client.Scopes,
			"is_public":      client.IsPublic,
			"auto_consent":   client.AutoConsent,
			"utime":          client.Utime,
		}).Error
}

func (dao *oauthClientDAO) UpdateSecret(ctx context.Context, id int64, secretHash string) error {
	return dao.db.WithContext(ctx).Model(&OAuthClient{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"client_secret_hash": secretHash,
			"utime":              time.Now().UnixMilli(),
		}).Error
}

func (dao *oauthClientDAO) FindByID(ctx context.Context, id int64) (OAuthClient, error) {
	var client OAuthClient
	err := dao.db.WithContext(ctx).Where("id = ?", id).First(&client).Error
	return client, err
}

func (dao *oauthClientDAO) FindByClientID(ctx context.Context, clientID string) (OAuthClient, error) {
	var client OAuthClient
	// client_id 是全局唯一索引键，OIDC 接入与令牌换发通常在未建立租户上下文或跨租户场景下触发，在此处使用 Scope 局域提权
	err := dao.db.WithContext(ctx).
		Scopes(gormx.IgnoreTenant()).
		Where("client_id = ?", clientID).
		First(&client).Error
	return client, err
}

func (dao *oauthClientDAO) ListByTenantID(ctx context.Context, tenantID int64, offset, limit int) ([]OAuthClient, int64, error) {
	var clients []OAuthClient
	var total int64
	query := dao.db.WithContext(ctx).Model(&OAuthClient{}).Where("tenant_id = ?", tenantID)
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	err := query.Order("id DESC").Offset(offset).Limit(limit).Find(&clients).Error
	return clients, total, err
}

func (dao *oauthClientDAO) Delete(ctx context.Context, id int64) error {
	return dao.db.WithContext(ctx).Where("id = ?", id).Delete(&OAuthClient{}).Error
}
