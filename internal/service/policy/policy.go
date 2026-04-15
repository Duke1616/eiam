package policy

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/dao"
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
	// AttachPolicyToUser 挂载托管策略到用户，用户将立即获得该策略定义的权限
	AttachPolicyToUser(ctx context.Context, username, polyCode string) error
	// AttachPolicyToRole 挂载托管策略到角色，角色将立即获得该策略定义的权限
	AttachPolicyToRole(ctx context.Context, roleCode, polyCode string) error
	// DetachFromUser 移除用户的托管策略
	DetachFromUser(ctx context.Context, username, polyCode string) error
	// DetachFromRole 移除角色的托管策略
	DetachFromRole(ctx context.Context, roleCode, polyCode string) error
	// GetAttachedPolicies 获取角色关联的托管策略
	GetAttachedPolicies(ctx context.Context, roleCode string) ([]domain.Policy, error)
	// GetAttachedPoliciesByCodes 批量获取角色关联的托管策略
	GetAttachedPoliciesByCodes(ctx context.Context, roleCodes []string) (map[string][]domain.Policy, error)
	// GetAttachedBySubjects 批量获取多个主体当前挂载的所有托管策略实体映射
	GetAttachedBySubjects(ctx context.Context, subjects []domain.Subject) (map[string][]domain.Policy, error)
	// ListAssignments 分页获取策略分配关系
	ListAssignments(ctx context.Context, offset, limit int64, subType string, keyword string) ([]dao.PolicyAssignment, int64, error)
	// ListByCodes 根据一组策略标识码获取策略详情
	ListByCodes(ctx context.Context, codes []string) ([]domain.Policy, error)
	// ListByTypes 获取指定类型的策略列表
	ListByTypes(ctx context.Context, types []domain.PolicyType) ([]domain.Policy, error)
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

func (s *policyService) AttachPolicyToUser(ctx context.Context, username, polyCode string) error {
	return s.repo.Attach(ctx, domain.SubjectTypeUser, username, polyCode)
}

func (s *policyService) AttachPolicyToRole(ctx context.Context, roleCode, polyCode string) error {
	return s.repo.Attach(ctx, domain.SubjectTypeRole, roleCode, polyCode)
}

func (s *policyService) DetachFromUser(ctx context.Context, username, polyCode string) error {
	return s.repo.Detach(ctx, domain.SubjectTypeUser, username, polyCode)
}

func (s *policyService) DetachFromRole(ctx context.Context, roleCode, polyCode string) error {
	return s.repo.Detach(ctx, domain.SubjectTypeRole, roleCode, polyCode)
}

func (s *policyService) GetAttachedPolicies(ctx context.Context, roleCode string) ([]domain.Policy, error) {
	return s.repo.GetAttached(ctx, domain.SubjectTypeRole, roleCode)
}

func (s *policyService) GetAttachedPoliciesByCodes(ctx context.Context, roleCodes []string) (map[string][]domain.Policy, error) {
	if len(roleCodes) == 0 {
		return make(map[string][]domain.Policy), nil
	}
	// 构建主体
	var subjects []domain.Subject
	for _, code := range roleCodes {
		subjects = append(subjects, domain.Subject{Type: domain.SubjectTypeRole, ID: code})
	}
	return s.repo.GetAttachedBySubjects(ctx, subjects)
}

func (s *policyService) GetAttachedBySubjects(ctx context.Context, subjects []domain.Subject) (map[string][]domain.Policy, error) {
	return s.repo.GetAttachedBySubjects(ctx, subjects)
}

func (s *policyService) ListAssignments(ctx context.Context, offset, limit int64, subType string, keyword string) ([]dao.PolicyAssignment, int64, error) {
	return s.repo.ListAssignments(ctx, offset, limit, subType, keyword)
}

func (s *policyService) ListByCodes(ctx context.Context, codes []string) ([]domain.Policy, error) {
	if len(codes) == 0 {
		return []domain.Policy{}, nil
	}
	return s.repo.ListByCodes(ctx, codes)
}

func (s *policyService) ListByTypes(ctx context.Context, types []domain.PolicyType) ([]domain.Policy, error) {
	if len(types) == 0 {
		return []domain.Policy{}, nil
	}
	return s.repo.ListByTypes(ctx, types)
}
