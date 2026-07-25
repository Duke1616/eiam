package role

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/permission/checker"
	"github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/casbin/casbin/v2"
	"golang.org/x/sync/errgroup"
)

// IRoleService 角色业务服务接口
//
//go:generate mockgen -source=./role.go -package=rolemocks -destination=./mocks/role.mock.go -typed IRoleService
type IRoleService interface {
	// Create 创建角色
	Create(ctx context.Context, r domain.Role) (int64, error)
	// List 获取角色列表
	List(ctx context.Context, offset, limit int64) ([]domain.Role, int64, error)
	// Search 模糊查询
	Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.Role, error)
	// CountByKeyword 根据关键词获取符合条件的角色总数
	CountByKeyword(ctx context.Context, keyword string) (int64, error)
	// Update 更新角色信息
	Update(ctx context.Context, r domain.Role) (int64, error)
	// UpdateInlinePolicies 修改角色的内联权限策略文档
	UpdateInlinePolicies(ctx context.Context, roleCode string, policies []domain.Policy) error
	// GetByCode 根据角色代码获取角色
	GetByCode(ctx context.Context, code string) (domain.Role, error)
	// ListAttachedRoles 分页获取主体关联的角色详情，支持关键词过滤
	ListAttachedRoles(ctx context.Context, username string, offset, limit int64, keyword string) ([]domain.Role, int64, error)
	// ListByIncludeCodes 查找包含当前角色代码的数据 (供鉴权中心调用)
	ListByIncludeCodes(ctx context.Context, codes []string) ([]domain.Role, error)
	// Delete 删除角色
	Delete(ctx context.Context, id int64) error
	// BatchDelete 批量删除角色
	BatchDelete(ctx context.Context, ids []int64) (int64, error)
	// GetByIDs 根据 ID 批量获取角色
	GetByIDs(ctx context.Context, ids []int64) ([]domain.Role, error)
}

type roleService struct {
	repo      repository.IRoleRepository
	policySvc policy.IPolicyService
	boundary  checker.IBoundaryChecker
	enforcer  *casbin.SyncedEnforcer
}

// NewRoleService 创建角色服务实例
func NewRoleService(repo repository.IRoleRepository, policySvc policy.IPolicyService,
	boundary checker.IBoundaryChecker, enforcer *casbin.SyncedEnforcer) IRoleService {
	return &roleService{
		repo:      repo,
		policySvc: policySvc,
		boundary:  boundary,
		enforcer:  enforcer,
	}
}

func (s *roleService) Create(ctx context.Context, r domain.Role) (int64, error) {
	if r.TenantID == 0 {
		r.TenantID = ctxutil.GetTenantID(ctx).Int64()
	}
	return s.repo.Create(ctx, r)
}

func (s *roleService) List(ctx context.Context, offset, limit int64) ([]domain.Role, int64, error) {
	total, err := s.repo.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	rs, err := s.repo.List(ctx, offset, limit)
	return rs, total, err
}

func (s *roleService) Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.Role, error) {
	if limit <= 0 {
		return []domain.Role{}, nil
	}

	return s.repo.Search(ctx, keyword, offset, limit)
}

func (s *roleService) CountByKeyword(ctx context.Context, keyword string) (int64, error) {
	return s.repo.CountByKeyword(ctx, keyword)
}

func (s *roleService) Update(ctx context.Context, r domain.Role) (int64, error) {
	if r.TenantID == 0 {
		r.TenantID = ctxutil.GetTenantID(ctx).Int64()
	}
	return s.repo.Update(ctx, r)
}

func (s *roleService) UpdateInlinePolicies(ctx context.Context, roleCode string, policies []domain.Policy) error {
	// 1. 安全校验：防止通过内联策略非法注入系统级权限
	for _, p := range policies {
		if err := policy.ValidatePolicyExpressions(p); err != nil {
			return err
		}
		if err := s.boundary.ValidateActionScopes(ctx, p.CollectActions()); err != nil {
			return err
		}
	}

	return s.repo.UpdateInlinePolicies(ctx, roleCode, policies)
}

func (s *roleService) GetByCode(ctx context.Context, code string) (domain.Role, error) {
	var (
		eg      errgroup.Group
		role    domain.Role
		managed []domain.Policy
	)

	eg.Go(func() error {
		var err error
		role, err = s.repo.GetByCode(ctx, code)
		return err
	})

	eg.Go(func() error {
		var err error
		managed, err = s.policySvc.GetAttachedPolicies(ctx, code)
		return err
	})

	if err := eg.Wait(); err != nil {
		return domain.Role{}, err
	}

	role.ManagedPolicies = managed
	return role, nil
}

func (s *roleService) ListByIncludeCodes(ctx context.Context, codes []string) ([]domain.Role, error) {
	if len(codes) == 0 {
		return []domain.Role{}, nil
	}

	roles, err := s.repo.ListByIncludeCodes(ctx, codes)
	if err != nil {
		return nil, err
	}

	// 一次性批量补全所有角色的托管策略，避免 N+1
	managedMap, err := s.policySvc.GetAttachedPoliciesByCodes(ctx, codes)
	if err != nil {
		return nil, err
	}

	for i := range roles {
		roles[i].ManagedPolicies = managedMap[roles[i].Code]
	}

	return roles, nil
}

func (s *roleService) ListAttachedRoles(ctx context.Context, username string, offset, limit int64, keyword string) ([]domain.Role, int64, error) {
	return s.repo.GetAttachedWithPagination(ctx, username, offset, limit, keyword)
}

func (s *roleService) Delete(ctx context.Context, id int64) error {
	// 1. 获取角色详情
	role, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// 2. 校验系统内置与保留角色 (不允许删除)
	if role.Type == domain.RoleTypeSystem || role.Code == "super_admin" || role.Code == "admin" {
		return errs.ErrDeleteSystemRole
	}

	// 3. 校验关联性 (是否有用户绑定、或作为父角色被继承)
	// Casbin 规则格式: g, v0, v1, v2 (ptype, sub, obj, domain)
	// 在我们的场景中，v1 始终是角色标识码 (domain.RoleSubject(role.Code))
	bindings, err := s.enforcer.GetFilteredGroupingPolicy(1, domain.RoleSubject(role.Code))
	if err != nil {
		return err
	}

	if len(bindings) > 0 {
		return errs.ErrRoleInUse
	}

	return s.repo.Delete(ctx, id)
}

func (s *roleService) GetByIDs(ctx context.Context, ids []int64) ([]domain.Role, error) {
	return s.repo.GetByIDs(ctx, ids)
}

func (s *roleService) BatchDelete(ctx context.Context, ids []int64) (int64, error) {
	// 1. 批量获取角色详情进行校验
	roles, err := s.repo.GetByIDs(ctx, ids)
	if err != nil {
		return 0, err
	}

	roleSubjects := make([]string, 0, len(roles))
	for _, role := range roles {
		// 2. 校验系统内置与保留角色 (不允许删除)
		if role.Type == domain.RoleTypeSystem || role.Code == "super_admin" || role.Code == "admin" {
			return 0, errs.ErrDeleteSystemRole
		}
		roleSubjects = append(roleSubjects, domain.RoleSubject(role.Code))
	}

	// 3. 批量校验关联性 (是否有用户绑定、或作为父角色被继承)
	usedSubjects, err := s.repo.CheckRolesUsage(ctx, roleSubjects)
	if err != nil {
		return 0, err
	}

	if len(usedSubjects) > 0 {
		return 0, errs.ErrRoleInUse
	}

	return s.repo.BatchDelete(ctx, ids)
}
