package role

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/pkg/ctxutil"
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
	// ListByIncludeCodes 查找包含当前角色代码的数据 (供鉴权中心调用)
	ListByIncludeCodes(ctx context.Context, codes []string) ([]domain.Role, error)
}

type roleService struct {
	repo      repository.IRoleRepository
	policySvc policy.IPolicyService
}

// NewRoleService 创建角色服务实例
func NewRoleService(repo repository.IRoleRepository, policySvc policy.IPolicyService) IRoleService {
	return &roleService{
		repo:      repo,
		policySvc: policySvc,
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
