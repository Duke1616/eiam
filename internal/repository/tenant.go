package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/ecodeclub/ekit/slice"
)

// ITenantRepository 租户仓储接口
type ITenantRepository interface {
	// Create 创建租户领域模型记录
	Create(ctx context.Context, t domain.Tenant) (int64, error)
	// FindById 根据 ID 获取租户领域模型
	FindById(ctx context.Context, id int64) (domain.Tenant, error)
	// FindByCode 根据 Code 获取租户领域模型
	FindByCode(ctx context.Context, code string) (domain.Tenant, error)
	// FindAll 分页获取租户领域模型列表
	FindAll(ctx context.Context, offset, limit int64) ([]domain.Tenant, error)
	// Count 统计租户总数
	Count(ctx context.Context) (int64, error)
	// Update 更新租户领域模型
	Update(ctx context.Context, t domain.Tenant) error
	// Delete 删除租户记录
	Delete(ctx context.Context, id int64) error

	// --- Membership 纯净契约管理 ---

	// AddMembership 建立用户与租户的关联契约（入驻）
	AddMembership(ctx context.Context, userID, tenantID int64) error
	// GetMembership 获取用户在特定租户下的契约详情
	GetMembership(ctx context.Context, tenantId, userId int64) (domain.Membership, error)
	// FindTenantsByUserId 获取指定用户关联的所有租户领域模型列表
	FindTenantsByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error)
	// GetAttachedTenantsWithFilter 分页模糊查询关联用户的租户
	GetAttachedTenantsWithFilter(ctx context.Context, userID, tid, offset, limit int64, keyword string) ([]domain.Tenant, int64, error)
	// FindMembershipsByUserIds 批量检索一组用户的入驻关联记录
	FindMembershipsByUserIds(ctx context.Context, userIds []int64) ([]domain.Membership, error)
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

func (r *TenantRepository) FindAll(ctx context.Context, offset, limit int64) ([]domain.Tenant, error) {
	ts, err := r.dao.FindAll(ctx, offset, limit)
	if err != nil {
		return nil, err
	}
	res := make([]domain.Tenant, 0, len(ts))
	for _, t := range ts {
		res = append(res, r.toDomain(t))
	}
	return res, nil
}

func (r *TenantRepository) Count(ctx context.Context) (int64, error) {
	return r.dao.Count(ctx)
}

func (r *TenantRepository) Update(ctx context.Context, t domain.Tenant) error {
	return r.dao.Update(ctx, dao.Tenant{
		ID:     t.ID,
		Name:   t.Name,
		Code:   t.Code,
		Domain: t.Domain,
		Status: t.Status,
	})
}

func (r *TenantRepository) Delete(ctx context.Context, id int64) error {
	return r.dao.Delete(ctx, id)
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

func (r *TenantRepository) GetAttachedTenantsWithFilter(ctx context.Context, userID, tid, offset, limit int64, keyword string) ([]domain.Tenant, int64, error) {
	ts, total, err := r.dao.GetAttachedTenantsWithFilter(ctx, userID, tid, offset, limit, keyword)
	if err != nil {
		return nil, 0, err
	}

	return slice.Map(ts, func(idx int, src dao.Tenant) domain.Tenant {
		return r.toDomain(src)
	}), total, nil
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
func (r *TenantRepository) FindMembershipsByUserIds(ctx context.Context, userIds []int64) ([]domain.Membership, error) {
	ms, err := r.dao.FindMembershipsByUserIds(ctx, userIds)
	if err != nil {
		return nil, err
	}

	return slice.Map(ms, func(idx int, src dao.Membership) domain.Membership {
		return domain.Membership{
			ID:       src.ID,
			TenantID: src.TenantID,
			UserID:   src.UserID,
		}
	}), nil
}
