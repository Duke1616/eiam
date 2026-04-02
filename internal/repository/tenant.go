package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
)

// ITenantRepository 租户仓储接口
type ITenantRepository interface {
	Create(ctx context.Context, t domain.Tenant) (int64, error)
	AddMember(ctx context.Context, m domain.Member) error
	FindById(ctx context.Context, id int64) (domain.Tenant, error)
	FindByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error)
	IsMember(ctx context.Context, tenantId, userId int64) (bool, error)
}

type TenantRepository struct {
	dao dao.ITenantDAO
}

func NewTenantRepository(d dao.ITenantDAO) ITenantRepository {
	return &TenantRepository{dao: d}
}

func (r *TenantRepository) Create(ctx context.Context, t domain.Tenant) (int64, error) {
	return r.dao.Insert(ctx, dao.Tenant{
		Name:    t.Name,
		Code:    t.Code,
		Type:    int8(t.Type),
		OwnerId: t.OwnerID,
		Status:  int8(t.Status),
	})
}

func (r *TenantRepository) AddMember(ctx context.Context, m domain.Member) error {
	return r.dao.InsertMember(ctx, dao.Member{
		TenantId: m.TenantID,
		UserId:   m.UserID,
		Status:   int8(m.Status),
	})
}

func (r *TenantRepository) FindById(ctx context.Context, id int64) (domain.Tenant, error) {
	t, err := r.dao.GetById(ctx, id)
	if err != nil {
		return domain.Tenant{}, err
	}
	return domain.Tenant{
		ID:      t.Id,
		Name:    t.Name,
		Code:    t.Code,
		Type:    domain.TenantType(t.Type),
		OwnerID: t.OwnerId,
		Status:  t.Status,
	}, nil
}

func (r *TenantRepository) FindByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error) {
	ts, err := r.dao.GetByUserId(ctx, userId)
	if err != nil {
		return nil, err
	}
	res := make([]domain.Tenant, len(ts))
	for i, t := range ts {
		res[i] = domain.Tenant{
			ID:      t.Id,
			Name:    t.Name,
			Code:    t.Code,
			Type:    domain.TenantType(t.Type),
			OwnerID: t.OwnerId,
			Status:  t.Status,
		}
	}
	return res, nil
}

func (r *TenantRepository) IsMember(ctx context.Context, tenantId, userId int64) (bool, error) {
	return r.dao.GetMember(ctx, tenantId, userId)
}
