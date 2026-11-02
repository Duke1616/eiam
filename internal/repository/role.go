package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/samber/lo"
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
	// Search 模糊查询
	Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.Role, error)
	// CountByKeyword 按关键字统计
	CountByKeyword(ctx context.Context, keyword string) (int64, error)
	// GetByCode 按代码获取
	GetByCode(ctx context.Context, code string) (domain.Role, error)
	// ListByIncludeCodes 按列表获取
	ListByIncludeCodes(ctx context.Context, codes []string) ([]domain.Role, error)
	// UpdateInlinePolicies 更新角色的权限策略列表
	UpdateInlinePolicies(ctx context.Context, code string, policies []domain.Policy) error
	// GetAttachedWithPagination 联表分页获取主体关联的角色详情，支持关键词过滤
	GetAttachedWithPagination(ctx context.Context, username string, offset, limit int64, keyword string) ([]domain.Role, int64, error)
	// Delete 删除角色
	Delete(ctx context.Context, id int64) error
	// BatchDelete 批量删除角色
	BatchDelete(ctx context.Context, ids []int64) (int64, error)
	// GetByID 根据 ID 获取角色
	GetByID(ctx context.Context, id int64) (domain.Role, error)
	// GetByIDs 根据 ID 批量获取角色
	GetByIDs(ctx context.Context, ids []int64) ([]domain.Role, error)
	// CheckRolesUsage 批量检查角色是否正在被使用
	CheckRolesUsage(ctx context.Context, roleCodes []string) ([]string, error)
}

type RoleRepository struct {
	dao   dao.IRoleDAO
	cache cache.IRoleCache
}

// NewRoleRepository 创建角色仓储实例
func NewRoleRepository(d dao.IRoleDAO, c cache.IRoleCache) IRoleRepository {
	return &RoleRepository{
		dao:   d,
		cache: c,
	}
}

func (r *RoleRepository) Create(ctx context.Context, role domain.Role) (int64, error) {
	return r.dao.Insert(ctx, r.toEntity(role))
}

func (r *RoleRepository) Update(ctx context.Context, role domain.Role) (int64, error) {
	rows, err := r.dao.Update(ctx, r.toEntity(role))
	if err != nil {
		return 0, err
	}
	// 角色元数据或描述变更，精准驱逐当前租户下的角色缓存
	if r.cache != nil && role.Code != "" {
		tid := ctxutil.GetTenantID(ctx).Int64()
		_ = r.cache.DeleteRoleByCode(ctx, tid, role.Code)
	}
	return rows, nil
}

func (r *RoleRepository) List(ctx context.Context, offset, limit int64) ([]domain.Role, error) {
	roles, err := r.dao.List(ctx, offset, limit)
	if err != nil {
		return nil, err
	}
	return lo.Map(roles, func(src dao.Role, _ int) domain.Role {
		return r.toDomain(src)
	}), nil
}

func (r *RoleRepository) Count(ctx context.Context) (int64, error) {
	return r.dao.Count(ctx)
}

func (r *RoleRepository) CountByKeyword(ctx context.Context, keyword string) (int64, error) {
	return r.dao.CountByKeyword(ctx, keyword)
}

func (r *RoleRepository) Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.Role, error) {
	roles, err := r.dao.Search(ctx, keyword, offset, limit)
	if err != nil {
		return nil, err
	}
	return lo.Map(roles, func(src dao.Role, _ int) domain.Role {
		return r.toDomain(src)
	}), nil
}

func (r *RoleRepository) GetByCode(ctx context.Context, code string) (domain.Role, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	if r.cache != nil {
		if role, hit, err := r.cache.GetRoleByCode(ctx, tid, code); err == nil && hit {
			return role, nil
		}
	}

	role, err := r.dao.GetByCode(ctx, code)
	if err != nil {
		return domain.Role{}, err
	}
	domainRole := r.toDomain(role)

	// 回填缓存（静默处理异常，不阻断主读取流程）
	if r.cache != nil {
		_ = r.cache.SetRoleByCode(ctx, tid, code, domainRole)
	}

	return domainRole, nil
}

func (r *RoleRepository) ListByIncludeCodes(ctx context.Context, codes []string) ([]domain.Role, error) {
	// 1. 去重并剔除空字符代码
	targetCodes := lo.Uniq(lo.Compact(codes))
	if len(targetCodes) == 0 {
		return []domain.Role{}, nil
	}

	tid := ctxutil.GetTenantID(ctx).Int64()

	// 2. 批量查缓存 (若缓存未命中或异常则自动降级为 targetCodes)
	cachedRoles, missingCodes := r.fetchRolesFromCache(ctx, tid, targetCodes)

	// 3. 增量查库并批量回填缓存
	if len(missingCodes) > 0 {
		loadedRoles, err := r.loadAndCacheMissingRoles(ctx, tid, missingCodes)
		if err != nil {
			return nil, err
		}
		for _, role := range loadedRoles {
			cachedRoles[role.Code] = role
		}
	}

	// 4. 按入参 codes 原序提取有效角色
	return lo.FilterMap(targetCodes, func(code string, _ int) (domain.Role, bool) {
		role, ok := cachedRoles[code]
		return role, ok
	}), nil
}

// fetchRolesFromCache 从缓存批量检索角色，遇到异常自动安全降级
func (r *RoleRepository) fetchRolesFromCache(ctx context.Context, tid int64, codes []string) (map[string]domain.Role, []string) {
	if r.cache == nil {
		return make(map[string]domain.Role, len(codes)), codes
	}
	hits, misses, err := r.cache.GetRolesByCodes(ctx, tid, codes)
	if err != nil {
		return make(map[string]domain.Role, len(codes)), codes
	}
	return hits, misses
}

// loadAndCacheMissingRoles 查库补齐缺失角色，利用 lo.UniqBy 保证多租户优先级并批量回填
func (r *RoleRepository) loadAndCacheMissingRoles(ctx context.Context, tid int64, codes []string) ([]domain.Role, error) {
	dbRoles, err := r.dao.ListByIncludeCodes(ctx, codes)
	if err != nil {
		return nil, err
	}

	// DAO 已按 tenant_id DESC 排序，通过 lo.UniqBy 保留每个 Code 优先级最高的一条（私有优先、全局兜底）
	dedupRoles := lo.UniqBy(dbRoles, func(r dao.Role) string { return r.Code })
	roles := lo.Map(dedupRoles, func(src dao.Role, _ int) domain.Role {
		return r.toDomain(src)
	})

	// 将新加载的角色通过 Pipeline 批量写入缓存
	if r.cache != nil && len(roles) > 0 {
		_ = r.cache.SetRoles(ctx, tid, roles)
	}
	return roles, nil
}

func (r *RoleRepository) GetAttachedWithPagination(ctx context.Context, username string, offset, limit int64, keyword string) ([]domain.Role, int64, error) {
	// 获取租户 ID 用于 Casbin 联表过滤 (Casbin 存储的是字符串形式)
	tid := ctxutil.GetTenantID(ctx).Int64()

	roles, total, err := r.dao.GetAttachedRolesWithFilter(ctx, username, tid, offset, limit, keyword)
	if err != nil {
		return nil, 0, err
	}

	return lo.Map(roles, func(src dao.Role, _ int) domain.Role {
		return r.toDomain(src)
	}), total, nil
}

func (r *RoleRepository) UpdateInlinePolicies(ctx context.Context, code string, policies []domain.Policy) error {
	if err := r.dao.UpdateInlinePolicies(ctx, code, policies); err != nil {
		return err
	}
	// 内联权限策略更新是鉴权决策变更的核心，立即驱逐缓存以保证强一致生效
	if r.cache != nil && code != "" {
		tid := ctxutil.GetTenantID(ctx).Int64()
		_ = r.cache.DeleteRoleByCode(ctx, tid, code)
	}
	return nil
}

func (r *RoleRepository) Delete(ctx context.Context, id int64) error {
	var roleCode string
	// 删除前读取 code 用于缓存淘汰
	if r.cache != nil {
		if entity, err := r.dao.GetByID(ctx, id); err == nil {
			roleCode = entity.Code
		}
	}

	if err := r.dao.Delete(ctx, id); err != nil {
		return err
	}

	if r.cache != nil && roleCode != "" {
		tid := ctxutil.GetTenantID(ctx).Int64()
		_ = r.cache.DeleteRoleByCode(ctx, tid, roleCode)
	}
	return nil
}

func (r *RoleRepository) BatchDelete(ctx context.Context, ids []int64) (int64, error) {
	var roleCodes []string
	if r.cache != nil && len(ids) > 0 {
		if entities, err := r.dao.FindByIDs(ctx, ids); err == nil {
			roleCodes = lo.Map(entities, func(e dao.Role, _ int) string {
				return e.Code
			})
		}
	}

	rows, err := r.dao.DeleteByIDs(ctx, ids)
	if err != nil {
		return 0, err
	}

	if r.cache != nil && len(roleCodes) > 0 {
		tid := ctxutil.GetTenantID(ctx).Int64()
		_ = r.cache.DeleteRolesByCodes(ctx, tid, roleCodes)
	}
	return rows, nil
}

func (r *RoleRepository) GetByID(ctx context.Context, id int64) (domain.Role, error) {
	role, err := r.dao.GetByID(ctx, id)
	if err != nil {
		return domain.Role{}, err
	}
	return r.toDomain(role), nil
}

func (r *RoleRepository) GetByIDs(ctx context.Context, ids []int64) ([]domain.Role, error) {
	roles, err := r.dao.FindByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	return lo.Map(roles, func(src dao.Role, _ int) domain.Role {
		return r.toDomain(src)
	}), nil
}

func (r *RoleRepository) CheckRolesUsage(ctx context.Context, roleCodes []string) ([]string, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	return r.dao.CheckRolesUsage(ctx, roleCodes, tid)
}

func (r *RoleRepository) toDomain(role dao.Role) domain.Role {
	return domain.Role{
		ID:             role.Id,
		TenantID:       role.TenantId,
		Code:           role.Code,
		Name:           role.Name,
		Desc:           role.Desc,
		Type:           role.Type,
		InlinePolicies: role.InlinePolicies.Val,
		Ctime:          role.Ctime,
		Utime:          role.Utime,
	}
}

func (r *RoleRepository) toEntity(role domain.Role) dao.Role {
	return dao.Role{
		Id:       role.ID,
		TenantId: role.TenantID,
		Code:     role.Code,
		Name:     role.Name,
		Desc:     role.Desc,
		Type:     role.Type,
		InlinePolicies: sqlx.JSONColumn[[]domain.Policy]{
			Val:   role.InlinePolicies,
			Valid: len(role.InlinePolicies) > 0,
		},
	}
}
