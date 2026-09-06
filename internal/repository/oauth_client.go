package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/samber/lo"
)

// IOAuthClientRepository 下游接入应用仓储接口
//
//go:generate mockgen -package=repomocks -destination=./mocks/oauth_client.mock.go github.com/Duke1616/eiam/internal/repository IOAuthClientRepository
type IOAuthClientRepository interface {
	// Create 创建接入应用
	Create(ctx context.Context, client domain.OAuthClient) (int64, error)
	// Update 更新应用配置
	Update(ctx context.Context, client domain.OAuthClient) error
	// UpdateSecret 更新应用密钥哈希
	UpdateSecret(ctx context.Context, id int64, secretHash string) error
	// FindByID 根据主键查询
	FindByID(ctx context.Context, id int64) (domain.OAuthClient, error)
	// FindByClientID 根据 ClientID 查询应用 (优先走缓存)
	FindByClientID(ctx context.Context, clientID string) (domain.OAuthClient, error)
	// ListByTenantID 租户级应用分页查询
	ListByTenantID(ctx context.Context, tenantID int64, offset, limit int) ([]domain.OAuthClient, int64, error)
	// Delete 删除应用
	Delete(ctx context.Context, id int64) error
}

type oauthClientRepository struct {
	dao   dao.IOAuthClientDAO
	cache cache.IOidcCache
}

// NewOAuthClientRepository 实例化接入应用仓储 (支持 Redis 高速缓存)
func NewOAuthClientRepository(dao dao.IOAuthClientDAO, cache cache.IOidcCache) IOAuthClientRepository {
	return &oauthClientRepository{
		dao:   dao,
		cache: cache,
	}
}

func (r *oauthClientRepository) Create(ctx context.Context, client domain.OAuthClient) (int64, error) {
	return r.dao.Create(ctx, r.toDao(client))
}

func (r *oauthClientRepository) Update(ctx context.Context, client domain.OAuthClient) error {
	err := r.dao.Update(ctx, r.toDao(client))
	if err == nil && r.cache != nil && client.ClientID != "" {
		_ = r.cache.DeleteOAuthClient(ctx, client.ClientID)
	}
	return err
}

func (r *oauthClientRepository) UpdateSecret(ctx context.Context, id int64, secretHash string) error {
	existing, err := r.dao.FindByID(ctx, id)
	if err != nil {
		return err
	}
	err = r.dao.UpdateSecret(ctx, id, secretHash)
	if err == nil && r.cache != nil && existing.ClientID != "" {
		_ = r.cache.DeleteOAuthClient(ctx, existing.ClientID)
	}
	return err
}

func (r *oauthClientRepository) FindByID(ctx context.Context, id int64) (domain.OAuthClient, error) {
	entity, err := r.dao.FindByID(ctx, id)
	if err != nil {
		return domain.OAuthClient{}, err
	}
	return r.toDomain(entity), nil
}

func (r *oauthClientRepository) FindByClientID(ctx context.Context, clientID string) (domain.OAuthClient, error) {
	if r.cache != nil {
		if data, err := r.cache.GetOAuthClient(ctx, clientID); err == nil && len(data) > 0 {
			var client domain.OAuthClient
			if unmarshalErr := json.Unmarshal(data, &client); unmarshalErr == nil {
				return client, nil
			}
		}
	}

	entity, err := r.dao.FindByClientID(ctx, clientID)
	if err != nil {
		return domain.OAuthClient{}, err
	}
	dom := r.toDomain(entity)

	if r.cache != nil {
		if data, err := json.Marshal(dom); err == nil {
			_ = r.cache.SaveOAuthClient(ctx, clientID, data)
		}
	}

	return dom, nil
}

func (r *oauthClientRepository) ListByTenantID(ctx context.Context, tenantID int64, offset, limit int) ([]domain.OAuthClient, int64, error) {
	entities, total, err := r.dao.ListByTenantID(ctx, tenantID, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	clients := lo.Map(entities, func(item dao.OAuthClient, _ int) domain.OAuthClient {
		return r.toDomain(item)
	})
	return clients, total, nil
}

func (r *oauthClientRepository) Delete(ctx context.Context, id int64) error {
	existing, err := r.dao.FindByID(ctx, id)
	if err != nil {
		return err
	}
	err = r.dao.Delete(ctx, id)
	if err == nil && r.cache != nil && existing.ClientID != "" {
		_ = r.cache.DeleteOAuthClient(ctx, existing.ClientID)
	}
	return err
}

func (r *oauthClientRepository) toDao(client domain.OAuthClient) dao.OAuthClient {
	return dao.OAuthClient{
		ID:               client.ID,
		TenantID:         client.TenantID,
		ClientID:         client.ClientID,
		ClientSecretHash: client.ClientSecretHash,
		Name:             client.Name,
		Logo:             client.Logo,
		RedirectURIs:     sqlx.JSONColumn[[]string]{Val: client.RedirectURIs, Valid: len(client.RedirectURIs) > 0},
		ResponseTypes:    sqlx.JSONColumn[[]string]{Val: client.ResponseTypes, Valid: len(client.ResponseTypes) > 0},
		GrantTypes:       sqlx.JSONColumn[[]string]{Val: client.GrantTypes, Valid: len(client.GrantTypes) > 0},
		Scopes:           sqlx.JSONColumn[[]string]{Val: client.Scopes, Valid: len(client.Scopes) > 0},
		IsPublic:         client.IsPublic,
		AutoConsent:      client.AutoConsent,
	}
}

func (r *oauthClientRepository) toDomain(entity dao.OAuthClient) domain.OAuthClient {
	return domain.OAuthClient{
		ID:               entity.ID,
		TenantID:         entity.TenantID,
		ClientID:         entity.ClientID,
		ClientSecretHash: entity.ClientSecretHash,
		Name:             entity.Name,
		Logo:             entity.Logo,
		RedirectURIs:     entity.RedirectURIs.Val,
		ResponseTypes:    entity.ResponseTypes.Val,
		GrantTypes:       entity.GrantTypes.Val,
		Scopes:           entity.Scopes.Val,
		IsPublic:         entity.IsPublic,
		AutoConsent:      entity.AutoConsent,
		Ctime:            time.UnixMilli(entity.Ctime),
		Utime:            time.UnixMilli(entity.Utime),
	}
}

