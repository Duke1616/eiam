package policy

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
)

// IPolicyService 策略管理服务：提供权限策略的生命周期管理与授权绑定逻辑
type IPolicyService interface {
	// CreatePolicy 创建权限策略
	CreatePolicy(ctx context.Context, p domain.Policy) (int64, error)
	// GetPolicy 获取策略详情
	GetPolicy(ctx context.Context, code string) (domain.Policy, error)
	// ListPolicies 分页获取策略列表
	ListPolicies(ctx context.Context, offset, limit int64) ([]domain.Policy, int64, error)
	UpdatePolicy(ctx context.Context, p domain.Policy) error
	// AttachPolicyToRole 挂载托管策略到角色，角色将立即获得该策略定义的权限
	AttachPolicyToRole(ctx context.Context, roleCode, polyCode string) error
	// DetachFromRole 移除角色的托管策略
	DetachFromRole(ctx context.Context, roleCode, polyCode string) error
	// GetAttachedPolicies 获取角色关联的托管策略
	GetAttachedPolicies(ctx context.Context, roleCode string) ([]domain.Policy, error)
	// GetAttachedPoliciesByCodes 批量获取角色关联的托管策略
	GetAttachedPoliciesByCodes(ctx context.Context, roleCodes []string) (map[string][]domain.Policy, error)
}

type policyService struct {
	repo repository.IPolicyRepository
}

func NewPolicyService(repo repository.IPolicyRepository) IPolicyService {
	return &policyService{repo: repo}
}

func (s *policyService) CreatePolicy(ctx context.Context, p domain.Policy) (int64, error) {
	return s.repo.CreatePolicy(ctx, p)
}

func (s *policyService) GetPolicy(ctx context.Context, code string) (domain.Policy, error) {
	return s.repo.GetPolicyByCode(ctx, code)
}

func (s *policyService) ListPolicies(ctx context.Context, offset, limit int64) ([]domain.Policy, int64, error) {
	return s.repo.ListPolicies(ctx, offset, limit)
}

func (s *policyService) UpdatePolicy(ctx context.Context, p domain.Policy) error {
	return s.repo.UpdatePolicy(ctx, p)
}

func (s *policyService) AttachPolicyToRole(ctx context.Context, roleCode, polyCode string) error {
	return s.repo.AttachPolicyToRole(ctx, roleCode, polyCode)
}

func (s *policyService) DetachFromRole(ctx context.Context, roleCode, polyCode string) error {
	return s.repo.DetachPolicyFromRole(ctx, roleCode, polyCode)
}

func (s *policyService) GetAttachedPolicies(ctx context.Context, roleCode string) ([]domain.Policy, error) {
	return s.repo.GetAttachedPolicies(ctx, roleCode)
}

func (s *policyService) GetAttachedPoliciesByCodes(ctx context.Context, roleCodes []string) (map[string][]domain.Policy, error) {
	return s.repo.GetAttachedPoliciesByCodes(ctx, roleCodes)
}
