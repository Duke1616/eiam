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

// IApplicationRepository 下游接入应用仓储接口
//
//go:generate mockgen -package=repomocks -destination=./mocks/application.mock.go github.com/Duke1616/eiam/internal/repository IApplicationRepository
type IApplicationRepository interface {
	// Create 创建接入应用
	Create(ctx context.Context, app domain.Application) (int64, error)
	// Update 更新应用配置
	Update(ctx context.Context, app domain.Application) error
	// UpdateSecret 更新应用密钥哈希
	UpdateSecret(ctx context.Context, id int64, secretHash string) error
	// FindByID 根据主键查询
	FindByID(ctx context.Context, id int64) (domain.Application, error)
	// FindByClientID 根据 ClientID 查询应用 (优先走缓存)
	FindByClientID(ctx context.Context, clientID string) (domain.Application, error)
	// ListByTenantID 租户级应用分页查询
	ListByTenantID(ctx context.Context, tenantID int64, offset, limit int) ([]domain.Application, int64, error)
	// Delete 删除应用
	Delete(ctx context.Context, id int64) error
}

type applicationRepository struct {
	dao   dao.IApplicationDAO
	cache cache.IOidcCache
}

// NewApplicationRepository 实例化接入应用仓储 (支持 Redis 高速缓存)
func NewApplicationRepository(dao dao.IApplicationDAO, cache cache.IOidcCache) IApplicationRepository {
	return &applicationRepository{
		dao:   dao,
		cache: cache,
	}
}

func (r *applicationRepository) Create(ctx context.Context, app domain.Application) (int64, error) {
	return r.dao.Create(ctx, r.toDao(app))
}

func (r *applicationRepository) Update(ctx context.Context, app domain.Application) error {
	err := r.dao.Update(ctx, r.toDao(app))
	if err == nil && r.cache != nil && app.ClientID != "" {
		_ = r.cache.DeleteApplication(ctx, app.ClientID)
	}
	return err
}

func (r *applicationRepository) UpdateSecret(ctx context.Context, id int64, secretHash string) error {
	existing, err := r.dao.FindByID(ctx, id)
	if err != nil {
		return err
	}
	err = r.dao.UpdateSecret(ctx, id, secretHash)
	if err == nil && r.cache != nil && existing.ClientID != "" {
		_ = r.cache.DeleteApplication(ctx, existing.ClientID)
	}
	return err
}

func (r *applicationRepository) FindByID(ctx context.Context, id int64) (domain.Application, error) {
	entity, err := r.dao.FindByID(ctx, id)
	if err != nil {
		return domain.Application{}, err
	}
	return r.toDomain(entity), nil
}

func (r *applicationRepository) FindByClientID(ctx context.Context, clientID string) (domain.Application, error) {
	if r.cache != nil {
		cachedData, err := r.cache.GetApplication(ctx, clientID)
		if err == nil && len(cachedData) > 0 {
			var app domain.Application
			if jsonErr := json.Unmarshal(cachedData, &app); jsonErr == nil {
				return app, nil
			}
		}
	}

	entity, err := r.dao.FindByClientID(ctx, clientID)
	if err != nil {
		return domain.Application{}, err
	}

	app := r.toDomain(entity)
	if r.cache != nil {
		if data, jsonErr := json.Marshal(app); jsonErr == nil {
			_ = r.cache.SaveApplication(ctx, clientID, data)
		}
	}

	return app, nil
}

func (r *applicationRepository) ListByTenantID(ctx context.Context, tenantID int64, offset, limit int) ([]domain.Application, int64, error) {
	entities, total, err := r.dao.ListByTenantID(ctx, tenantID, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	return lo.Map(entities, func(src dao.Application, _ int) domain.Application {
		return r.toDomain(src)
	}), total, nil
}

func (r *applicationRepository) Delete(ctx context.Context, id int64) error {
	existing, err := r.dao.FindByID(ctx, id)
	if err != nil {
		return err
	}
	err = r.dao.Delete(ctx, id)
	if err == nil && r.cache != nil && existing.ClientID != "" {
		_ = r.cache.DeleteApplication(ctx, existing.ClientID)
	}
	return err
}

func (r *applicationRepository) toDao(app domain.Application) dao.Application {
	protocol := string(app.Protocol)
	if protocol == "" {
		protocol = string(domain.ProtocolOIDC)
	}
	return dao.Application{
		ID:               app.ID,
		TenantID:         app.TenantID,
		Protocol:         protocol,
		ClientID:         app.ClientID,
		ClientSecretHash: app.ClientSecretHash,
		Name:             app.Name,
		Logo:             app.Logo,
		RedirectURIs:     sqlx.JSONColumn[[]string]{Val: app.RedirectURIs, Valid: len(app.RedirectURIs) > 0},
		ResponseTypes:    sqlx.JSONColumn[[]string]{Val: app.ResponseTypes, Valid: len(app.ResponseTypes) > 0},
		GrantTypes:       sqlx.JSONColumn[[]string]{Val: app.GrantTypes, Valid: len(app.GrantTypes) > 0},
		Scopes:           sqlx.JSONColumn[[]string]{Val: app.Scopes, Valid: len(app.Scopes) > 0},
		IsPublic:         app.IsPublic,
		AutoConsent:      app.AutoConsent,
	}
}

func (r *applicationRepository) toDomain(entity dao.Application) domain.Application {
	protocol := domain.Protocol(entity.Protocol)
	if protocol == "" {
		protocol = domain.ProtocolOIDC
	}
	return domain.Application{
		ID:               entity.ID,
		TenantID:         entity.TenantID,
		Protocol:         protocol,
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
