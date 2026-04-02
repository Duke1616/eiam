package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/ecodeclub/ekit/slice"
)

// ITenantRepository 租户仓储接口
type ITenantRepository interface {
	Create(ctx context.Context, t domain.Tenant) (int64, error)
	FindById(ctx context.Context, id int64) (domain.Tenant, error)
	FindByCode(ctx context.Context, code string) (domain.Tenant, error)
	FindAll(ctx context.Context) ([]domain.Tenant, error)

	// --- Membership 纯净契约管理 ---

	AddMembership(ctx context.Context, userID, tenantID int64) error
	GetMembership(ctx context.Context, tenantId, userId int64) (domain.Membership, error)
	FindTenantsByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error)
}

type TenantRepository struct {
	dao dao.ITenantDAO
}

func NewTenantRepository(d dao.ITenantDAO) ITenantRepository {
	return &TenantRepository{dao: d}
}

func (r *TenantRepository) Create(ctx context.Context, t domain.Tenant) (int64, error) {
	return r.dao.Create(ctx, dao.Tenant{
		Name:   t.Name,
		Code:   t.Code,
		Domain: t.Domain,
		Status: t.Status,
	})
}

func (r *TenantRepository) AddMembership(ctx context.Context, userID, tenantID int64) error {
	return r.dao.InsertMembership(ctx, dao.Membership{
		TenantID: tenantID,
		UserID:   userID,
	})
}

func (r *TenantRepository) GetMembership(ctx context.Context, tenantId, userId int64) (domain.Membership, error) {
	m, err := r.dao.GetMembership(ctx, tenantId, userId)
	if err != nil {
		return domain.Membership{}, err
	}
	return domain.Membership{
		ID:       m.ID,
		TenantID: m.TenantID,
		UserID:   m.UserID,
		Ctime:    m.Ctime,
	}, nil
}

func (r *TenantRepository) FindById(ctx context.Context, id int64) (domain.Tenant, error) {
	t, err := r.dao.FindById(ctx, id)
	if err != nil {
		return domain.Tenant{}, err
	}
	return r.toDomain(t), nil
}

func (r *TenantRepository) FindByCode(ctx context.Context, code string) (domain.Tenant, error) {
	t, err := r.dao.FindByCode(ctx, code)
	if err != nil {
		return domain.Tenant{}, err
	}
	return r.toDomain(t), nil
}

func (r *TenantRepository) FindAll(ctx context.Context) ([]domain.Tenant, error) {
	ts, err := r.dao.FindAll(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]domain.Tenant, 0, len(ts))
	for _, t := range ts {
		res = append(res, r.toDomain(t))
	}
	return res, nil
}

func (r *TenantRepository) FindTenantsByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error) {
	// 从 membership 表查出该用户入驻的所有租户 ID
	ids, err := r.dao.FindTenantIDsByUserId(ctx, userId)
	if err != nil || len(ids) == 0 {
		return nil, err
	}

	// 按 ID 列表批量查租户详情（IN 查询，走主键索引）
	ts, err := r.dao.FindTenantsByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}

	return slice.Map(ts, func(idx int, src dao.Tenant) domain.Tenant {
		return r.toDomain(src)
	}), nil
}

func (r *TenantRepository) toDomain(t dao.Tenant) domain.Tenant {
	return domain.Tenant{
		ID:     t.ID,
		Name:   t.Name,
		Code:   t.Code,
		Domain: t.Domain,
		Status: t.Status,
		Ctime:  t.Ctime,
		Utime:  t.Utime,
	}
}
