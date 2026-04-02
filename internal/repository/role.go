package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/ecodeclub/ekit/slice"
)

// IRoleRepository 角色仓储接口
type IRoleRepository interface {
	// Create 新增角色
	Create(ctx context.Context, r domain.Role) (int64, error)
	// Update 更新角色
	Update(ctx context.Context, r domain.Role) (int64, error)
	// List 分页查询
	List(ctx context.Context, tenantId int64, offset, limit int64) ([]domain.Role, error)
	// Count 统计数量
	Count(ctx context.Context, tenantId int64) (int64, error)
	// GetByCode 按代码获取
	GetByCode(ctx context.Context, tenantId int64, code string) (domain.Role, error)
	// ListByIncludeCodes 按列表获取
	ListByIncludeCodes(ctx context.Context, tenantId int64, codes []string) ([]domain.Role, error)
	// UpdatePolicies 更新角色的权限策略列表 (AWS 风格)
	UpdatePolicies(ctx context.Context, tenantId int64, code string, policies []domain.Policy) error
}

type RoleRepository struct {
	dao dao.IRoleDAO
}

func NewRoleRepository(d dao.IRoleDAO) IRoleRepository {
	return &RoleRepository{dao: d}
}

func (r *RoleRepository) Create(ctx context.Context, role domain.Role) (int64, error) {
	return r.dao.Insert(ctx, r.toEntity(role))
}

func (r *RoleRepository) Update(ctx context.Context, role domain.Role) (int64, error) {
	return r.dao.Update(ctx, r.toEntity(role))
}

func (r *RoleRepository) List(ctx context.Context, tenantId int64, offset, limit int64) ([]domain.Role, error) {
	roles, err := r.dao.List(ctx, tenantId, offset, limit)
	if err != nil {
		return nil, err
	}
	return slice.Map(roles, func(idx int, src dao.Role) domain.Role {
		return r.toDomain(src)
	}), nil
}

func (r *RoleRepository) Count(ctx context.Context, tenantId int64) (int64, error) {
	return r.dao.Count(ctx, tenantId)
}

func (r *RoleRepository) GetByCode(ctx context.Context, tenantId int64, code string) (domain.Role, error) {
	role, err := r.dao.GetByCode(ctx, tenantId, code)
	if err != nil {
		return domain.Role{}, err
	}
	return r.toDomain(role), nil
}

func (r *RoleRepository) ListByIncludeCodes(ctx context.Context, tenantId int64, codes []string) ([]domain.Role, error) {
	roles, err := r.dao.ListByIncludeCodes(ctx, tenantId, codes)
	if err != nil {
		return nil, err
	}
	return slice.Map(roles, func(idx int, src dao.Role) domain.Role {
		return r.toDomain(src)
	}), nil
}

func (r *RoleRepository) UpdatePolicies(ctx context.Context, tenantId int64, code string, policies []domain.Policy) error {
	return r.dao.UpdatePolicies(ctx, tenantId, code, policies)
}

func (r *RoleRepository) toDomain(role dao.Role) domain.Role {
	return domain.Role{
		ID:       role.Id,
		TenantID: role.TenantId,
		Code:     role.Code,
		Name:     role.Name,
		Desc:     role.Desc,
		Status:   role.Status,
		Policies: role.Policies.Val,
	}
}

func (r *RoleRepository) toEntity(role domain.Role) dao.Role {
	return dao.Role{
		Id:       role.ID,
		TenantId: role.TenantID,
		Code:     role.Code,
		Name:     role.Name,
		Desc:     role.Desc,
		Status:   role.Status,
		Policies: sqlx.JSONColumn[[]domain.Policy]{
			Val:   role.Policies,
			Valid: len(role.Policies) > 0,
		},
	}
}
