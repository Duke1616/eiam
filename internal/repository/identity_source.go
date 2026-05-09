package repository

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/samber/lo"
)

// IIdentitySourceRepository 身份源仓库接口
type IIdentitySourceRepository interface {
	// Save 持久化身份源配置
	Save(ctx context.Context, source domain.IdentitySource) (int64, error)

	// List 获取身份源列表
	List(ctx context.Context) ([]domain.IdentitySource, error)

	// GetByID 获取详情
	GetByID(ctx context.Context, id int64) (domain.IdentitySource, error)

	// GetEnabledProviderTypes 获取所有已启用的登录提供商类型（用于登录页展示按钮/标签）
	GetEnabledProviderTypes(ctx context.Context) ([]string, error)

	// GetEnabledByType 获取指定类型且已启用的身份源列表
	GetEnabledByType(ctx context.Context, sourceType domain.IdentitySourceType) ([]domain.IdentitySource, error)

	// Delete 删除记录
	Delete(ctx context.Context, id int64) error

	// SaveState 存储 OIDC State 与 Nonce (缓存 5 分钟)
	SaveState(ctx context.Context, state string, sourceID int64, nonce string) error

	// GetState 获取并删除 OIDC State (一次性)，返回 sourceID 和 nonce
	GetState(ctx context.Context, state string) (int64, string, error)

	// ToggleEnabled 切换身份源启用状态（取反）
	ToggleEnabled(ctx context.Context, id int64) error
}

type identitySourceRepository struct {
	dao   dao.IIdentitySourceDAO
	cache cache.IIdentitySourceCache
}

func NewIdentitySourceRepository(dao dao.IIdentitySourceDAO, cache cache.IIdentitySourceCache) IIdentitySourceRepository {
	return &identitySourceRepository{
		dao:   dao,
		cache: cache,
	}
}

func (r *identitySourceRepository) Save(ctx context.Context, source domain.IdentitySource) (int64, error) {
	return r.dao.Save(ctx, r.toDao(source))
}

func (r *identitySourceRepository) List(ctx context.Context) ([]domain.IdentitySource, error) {
	sources, err := r.dao.List(ctx)
	if err != nil {
		return nil, err
	}
	return lo.Map(sources, func(src dao.IdentitySource, _ int) domain.IdentitySource {
		return r.toDomain(src)
	}), nil
}

func (r *identitySourceRepository) GetByID(ctx context.Context, id int64) (domain.IdentitySource, error) {
	src, err := r.dao.GetByID(ctx, id)
	if err != nil {
		return domain.IdentitySource{}, err
	}
	return r.toDomain(src), nil
}

func (r *identitySourceRepository) Delete(ctx context.Context, id int64) error {
	return r.dao.Delete(ctx, id)
}

func (r *identitySourceRepository) GetEnabledProviderTypes(ctx context.Context) ([]string, error) {
	sources, err := r.dao.GetEnabled(ctx)
	if err != nil {
		return nil, err
	}

	res := lo.FilterMap(sources, func(src dao.IdentitySource, _ int) (string, bool) {
		switch domain.IdentitySourceType(src.Type) {
		case domain.LDAP, domain.LOCAL, domain.PASSKEY:
			return src.Type, true
		case domain.OIDC:
			return string(src.OIDCConfig.Val.ProviderType), true
		default:
			return "", false
		}
	})

	return lo.Uniq(res), nil
}

func (r *identitySourceRepository) SaveState(ctx context.Context, state string, sourceID int64, nonce string) error {
	return r.cache.SetState(ctx, state, sourceID, nonce)
}

func (r *identitySourceRepository) GetState(ctx context.Context, state string) (int64, string, error) {
	return r.cache.GetState(ctx, state)
}

func (r *identitySourceRepository) ToggleEnabled(ctx context.Context, id int64) error {
	return r.dao.ToggleEnabled(ctx, id)
}

func (r *identitySourceRepository) GetEnabledByType(ctx context.Context, sourceType domain.IdentitySourceType) ([]domain.IdentitySource, error) {
	sources, err := r.dao.GetEnabledByType(ctx, string(sourceType))
	if err != nil {
		return nil, err
	}

	return lo.Map(sources, func(src dao.IdentitySource, _ int) domain.IdentitySource {
		return r.toDomain(src)
	}), nil
}

func (r *identitySourceRepository) toDao(src domain.IdentitySource) dao.IdentitySource {
	return dao.IdentitySource{
		ID:   src.ID,
		Name: src.Name,
		Type: string(src.Type),
		LDAPConfig: sqlx.JSONColumn[domain.LDAPConfig]{
			Val:   src.LDAPConfig,
			Valid: true,
		},
		OIDCConfig: sqlx.JSONColumn[domain.OIDCConfig]{
			Val:   src.OIDCConfig,
			Valid: true,
		},
		LocalConfig: sqlx.JSONColumn[domain.LocalConfig]{
			Val:   src.LocalConfig,
			Valid: true,
		},
		PasskeyConfig: sqlx.JSONColumn[domain.PasskeyConfig]{
			Val:   src.PasskeyConfig,
			Valid: true,
		},
		Enabled: src.Enabled,
	}
}

func (r *identitySourceRepository) toDomain(src dao.IdentitySource) domain.IdentitySource {
	return domain.IdentitySource{
		ID:            src.ID,
		Name:          src.Name,
		Type:          domain.IdentitySourceType(src.Type),
		LDAPConfig:    src.LDAPConfig.Val,
		OIDCConfig:    src.OIDCConfig.Val,
		LocalConfig:   src.LocalConfig.Val,
		PasskeyConfig: src.PasskeyConfig.Val,
		Enabled:       src.Enabled,
		Ctime:         time.UnixMilli(src.Ctime),
		Utime:         time.UnixMilli(src.Utime),
	}
}
