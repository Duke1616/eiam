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
	List(ctx context.Context, offset, limit int64) ([]domain.Role, error)
	// Count 统计数量
	Count(ctx context.Context) (int64, error)
	// GetByCode 按代码获取
	GetByCode(ctx context.Context, code string) (domain.Role, error)
	// ListByIncludeCodes 按列表获取
	ListByIncludeCodes(ctx context.Context, codes []string) ([]domain.Role, error)
	// UpdateInlinePolicies 更新角色的权限策略列表
	UpdateInlinePolicies(ctx context.Context, code string, policies []domain.Policy) error
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

func (r *RoleRepository) List(ctx context.Context, offset, limit int64) ([]domain.Role, error) {
	roles, err := r.dao.List(ctx, offset, limit)
	if err != nil {
		return nil, err
	}
	return slice.Map(roles, func(idx int, src dao.Role) domain.Role {
		return r.toDomain(src)
	}), nil
}

func (r *RoleRepository) Count(ctx context.Context) (int64, error) {
	return r.dao.Count(ctx)
}

func (r *RoleRepository) GetByCode(ctx context.Context, code string) (domain.Role, error) {
	role, err := r.dao.GetByCode(ctx, code)
	if err != nil {
		return domain.Role{}, err
	}
	return r.toDomain(role), nil
}

func (r *RoleRepository) ListByIncludeCodes(ctx context.Context, codes []string) ([]domain.Role, error) {
	roles, err := r.dao.ListByIncludeCodes(ctx, codes)
	if err != nil {
		return nil, err
	}

	// 核心去重逻辑：同一个 Code 仅保留优先级最高的角色。
	// 由于 DAO 已经按 tenant_id DESC 排序，第一个被遇到的即为租户私有角色（若存在）。
	seen := make(map[string]struct{})
	res := make([]domain.Role, 0, len(roles))
	for _, role := range roles {
		if _, ok := seen[role.Code]; ok {
			continue
		}
		seen[role.Code] = struct{}{}
		res = append(res, r.toDomain(role))
	}

	return res, nil
}

func (r *RoleRepository) UpdateInlinePolicies(ctx context.Context, code string, policies []domain.Policy) error {
	return r.dao.UpdateInlinePolicies(ctx, code, policies)
}

func (r *RoleRepository) toDomain(role dao.Role) domain.Role {
	return domain.Role{
		ID:             role.Id,
		TenantID:       role.TenantId,
		Code:           role.Code,
		Name:           role.Name,
		Desc:           role.Desc,
		Status:         role.Status,
		Type:           role.Type,
		InlinePolicies: role.InlinePolicies.Val,
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
		Type:     role.Type,
		InlinePolicies: sqlx.JSONColumn[[]domain.Policy]{
			Val:   role.InlinePolicies,
			Valid: len(role.InlinePolicies) > 0,
		},
	}
}
