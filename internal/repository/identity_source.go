package repository

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/ecodeclub/ekit/slice"
)

// IIdentitySourceRepository 身份源仓库接口
type IIdentitySourceRepository interface {
	// Save 持久化身份源配置
	Save(ctx context.Context, source domain.IdentitySource) (int64, error)

	// List 获取身份源列表（受租户插件自动隔离）
	List(ctx context.Context) ([]domain.IdentitySource, error)

	// GetByID 获取详情
	GetByID(ctx context.Context, id int64) (domain.IdentitySource, error)

	// Delete 删除记录
	Delete(ctx context.Context, id int64) error
}

type identitySourceRepository struct {
	dao dao.IIdentitySourceDAO
}

func NewIdentitySourceRepository(dao dao.IIdentitySourceDAO) IIdentitySourceRepository {
	return &identitySourceRepository{dao: dao}
}

func (r *identitySourceRepository) Save(ctx context.Context, source domain.IdentitySource) (int64, error) {
	return r.dao.Save(ctx, r.toDao(source))
}

func (r *identitySourceRepository) List(ctx context.Context) ([]domain.IdentitySource, error) {
	sources, err := r.dao.List(ctx)
	if err != nil {
		return nil, err
	}
	return slice.Map(sources, func(idx int, src dao.IdentitySource) domain.IdentitySource {
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

func (r *identitySourceRepository) toDao(src domain.IdentitySource) dao.IdentitySource {
	return dao.IdentitySource{
		ID:   src.ID,
		Name: src.Name,
		Type: string(src.Type),
		LDAPConfig: sqlx.JSONColumn[domain.LDAPConfig]{
			Val:   src.LDAPConfig,
			Valid: true,
		},
		Enabled: src.Enabled,
	}
}

func (r *identitySourceRepository) toDomain(src dao.IdentitySource) domain.IdentitySource {
	return domain.IdentitySource{
		ID:         src.ID,
		Name:       src.Name,
		Type:       domain.IdentitySourceType(src.Type),
		LDAPConfig: src.LDAPConfig.Val,
		Enabled:    src.Enabled,
		Ctime:      time.UnixMilli(src.Ctime),
		Utime:      time.UnixMilli(src.Utime),
	}
}
