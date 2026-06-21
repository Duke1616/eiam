package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/ecodeclub/ekit/slice"
)

// ITenantKeyRepository 租户密钥仓储接口：负责凭证领域模型与持久化实体的转换和媒介管理
type ITenantKeyRepository interface {
	// Create 持久化保存新凭证记录
	Create(ctx context.Context, tk domain.TenantKey) (int64, error)
	// FindByAccessKey 根据唯一 AccessKey 匹配查找凭证记录
	FindByAccessKey(ctx context.Context, ak string) (domain.TenantKey, error)
	// ListByTenantID 检索指定租户下的所有凭证数据
	ListByTenantID(ctx context.Context, tenantID int64) ([]domain.TenantKey, error)
	// UpdateStatus 修改凭证的生效状态
	UpdateStatus(ctx context.Context, id int64, status int) error
}

type TenantKeyRepository struct {
	dao dao.ITenantKeyDAO
}

func NewTenantKeyRepository(d dao.ITenantKeyDAO) ITenantKeyRepository {
	return &TenantKeyRepository{dao: d}
}

func (r *TenantKeyRepository) Create(ctx context.Context, tk domain.TenantKey) (int64, error) {
	return r.dao.Create(ctx, dao.TenantKey{
		TenantID:    tk.TenantID,
		AccessKey:   tk.AccessKey,
		SecretKey:   tk.SecretKey,
		Status:      tk.Status,
		Description: tk.Description,
	})
}

func (r *TenantKeyRepository) FindByAccessKey(ctx context.Context, ak string) (domain.TenantKey, error) {
	tk, err := r.dao.FindByAccessKey(ctx, ak)
	if err != nil {
		return domain.TenantKey{}, err
	}
	return r.toDomain(tk), nil
}

func (r *TenantKeyRepository) ListByTenantID(ctx context.Context, tenantID int64) ([]domain.TenantKey, error) {
	tks, err := r.dao.ListByTenantID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return slice.Map(tks, func(idx int, src dao.TenantKey) domain.TenantKey {
		return r.toDomain(src)
	}), nil
}

func (r *TenantKeyRepository) UpdateStatus(ctx context.Context, id int64, status int) error {
	return r.dao.UpdateStatus(ctx, id, status)
}

func (r *TenantKeyRepository) toDomain(tk dao.TenantKey) domain.TenantKey {
	return domain.TenantKey{
		ID:          tk.ID,
		TenantID:    tk.TenantID,
		AccessKey:   tk.AccessKey,
		SecretKey:   tk.SecretKey,
		Status:      tk.Status,
		Description: tk.Description,
		Ctime:       tk.Ctime,
		Utime:       tk.Utime,
	}
}
