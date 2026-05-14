package policy

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/internal/service/permission/checker"
)

// IPolicyService 策略管理服务：提供权限策略的生命周期管理与授权绑定逻辑
type IPolicyService interface {
	// CreatePolicy 创建权限策略
	CreatePolicy(ctx context.Context, p domain.Policy) (int64, error)
	// GetPolicy 获取策略详情
	GetPolicy(ctx context.Context, code string) (domain.Policy, error)
	// ListPolicies 分页获取策略列表
	ListPolicies(ctx context.Context, offset, limit int64) ([]domain.Policy, int64, error)
	// SearchPolicies 关键词与类型搜索列表
	SearchPolicies(ctx context.Context, offset, limit int64, keyword string, policyType domain.PolicyType) ([]domain.Policy, int64, error)
	// UpdatePolicy 修改权限策略
	UpdatePolicy(ctx context.Context, p domain.Policy) error
	// AttachPolicyToUser 挂载托管策略到用户，用户将立即获得该策略定义的权限
	AttachPolicyToUser(ctx context.Context, username, policyCode string) error
	// AttachPolicyToRole 挂载托管策略到角色，角色将立即获得该策略定义的权限
	AttachPolicyToRole(ctx context.Context, roleCode, policyCode string) error
	// DetachFromUser 移除用户的托管策略
	DetachFromUser(ctx context.Context, username, policyCode string) error
	// DetachFromRole 移除角色的托管策略
	DetachFromRole(ctx context.Context, roleCode, policyCode string) error
	// Attach 将策略绑定到指定主体 (通用方法)
	Attach(ctx context.Context, subType, subCode, policyCode string) error
	// Detach 将策略从指定主体解绑 (通用方法)
	Detach(ctx context.Context, subType, subCode, policyCode string) error
	// GetAttachedPolicies 获取角色关联的托管策略
	GetAttachedPolicies(ctx context.Context, roleCode string) ([]domain.Policy, error)
	// GetAttachedPoliciesByCodes 批量获取角色关联的托管策略
	GetAttachedPoliciesByCodes(ctx context.Context, roleCodes []string) (map[string][]domain.Policy, error)
	// GetAttachedBySubjects 批量获取多个主体当前挂载的所有托管策略实体映射
	GetAttachedBySubjects(ctx context.Context, subjects []domain.Subject) (map[string][]domain.Policy, error)
	// GetAttachedWithPagination 分页获取主体当前挂载的策略实体
	GetAttachedWithPagination(ctx context.Context, subType, subCode string, offset, limit int64, keyword string, policyType domain.PolicyType) ([]domain.Policy, int64, error)
	// ListAttachedPolicies 分页获取主体关联的策略
	ListAttachedPolicies(ctx context.Context, subType, subCode string, offset, limit int64, keyword string, policyType domain.PolicyType) ([]domain.Policy, int64, error)
	// ListAssignments 分页获取策略分配关系
	ListAssignments(ctx context.Context, offset, limit int64, subType string, keyword string, policyType uint8) ([]dao.PolicyAssignment, int64, error)
	// ListByCodes 根据一组策略标识码获取策略详情
	ListByCodes(ctx context.Context, codes []string) ([]domain.Policy, error)
	// ListByTypes 获取指定类型的策略列表
	ListByTypes(ctx context.Context, types []domain.PolicyType) ([]domain.Policy, error)
	// BatchAttachPolicies 批量绑定策略到多个主体
	// 返回成功绑定的详细结果统计
	BatchAttachPolicies(ctx context.Context, subjects []domain.Subject, policyCodes []string) (domain.BatchResult, error)
	// BatchDetachPolicies 批量解绑策略
	BatchDetachPolicies(ctx context.Context, assignments []domain.SubjectPolicyAssignment) (int64, error)
	// DeletePolicy 删除权限策略
	DeletePolicy(ctx context.Context, code string) error
	// BatchDeletePolicies 批量删除权限策略
	BatchDeletePolicies(ctx context.Context, codes []string) error
}

type policyService struct {
	repo     repository.IPolicyRepository
	boundary checker.IBoundaryChecker
}

func NewPolicyService(repo repository.IPolicyRepository, boundary checker.IBoundaryChecker) IPolicyService {
	return &policyService{
		repo:     repo,
		boundary: boundary,
	}
}

func (s *policyService) CreatePolicy(ctx context.Context, p domain.Policy) (int64, error) {
	// 1. 安全校验：防止非法注入系统级权限
	if err := s.boundary.ValidateActionScopes(ctx, p.CollectActions()); err != nil {
		return 0, err
	}

	// 2. 冲突检测：防止当前租户自定义策略与当前租户已有策略，或与系统的公共预置策略（Type 1）冲突
	_, err := s.repo.GetPolicyByCode(ctx, p.Code)
	if err == nil {
		return 0, errs.ErrDuplicatePolicyCode
	}

	return s.repo.CreatePolicy(ctx, p)
}

func (s *policyService) UpdatePolicy(ctx context.Context, p domain.Policy) error {
	// 1. 安全校验：防止非法注入系统级权限
	if err := s.boundary.ValidateActionScopes(ctx, p.CollectActions()); err != nil {
		return err
	}

	return s.repo.UpdatePolicy(ctx, p)
}

func (s *policyService) GetPolicy(ctx context.Context, code string) (domain.Policy, error) {
	p, err := s.repo.GetPolicyByCode(ctx, code)
	if err != nil {
		return domain.Policy{}, err
	}

	// 填充授权数量统计
	ps := []domain.Policy{p}
	if err = s.repo.FillAssignmentCounts(ctx, ps); err != nil {
		return domain.Policy{}, err
	}

	return ps[0], nil
}

func (s *policyService) ListPolicies(ctx context.Context, offset, limit int64) ([]domain.Policy, int64, error) {
	ps, total, err := s.repo.ListPolicies(ctx, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	// 填充授权数量统计
	if err = s.repo.FillAssignmentCounts(ctx, ps); err != nil {
		return nil, 0, err
	}

	return ps, total, nil
}

func (s *policyService) SearchPolicies(ctx context.Context, offset, limit int64, keyword string, policyType domain.PolicyType) ([]domain.Policy, int64, error) {
	ps, total, err := s.repo.SearchPolicies(ctx, offset, limit, keyword, policyType)
	if err != nil {
		return nil, 0, err
	}

	// 填充授权数量统计
	if err = s.repo.FillAssignmentCounts(ctx, ps); err != nil {
		return nil, 0, err
	}

	return ps, total, nil
}

func (s *policyService) AttachPolicyToUser(ctx context.Context, username, policyCode string) error {
	return s.repo.Attach(ctx, domain.SubjectTypeUser, username, policyCode)
}

func (s *policyService) AttachPolicyToRole(ctx context.Context, roleCode, policyCode string) error {
	return s.repo.Attach(ctx, domain.SubjectTypeRole, roleCode, policyCode)
}

func (s *policyService) DetachFromUser(ctx context.Context, username, policyCode string) error {
	return s.repo.Detach(ctx, domain.SubjectTypeUser, username, policyCode)
}

func (s *policyService) DetachFromRole(ctx context.Context, roleCode, policyCode string) error {
	return s.repo.Detach(ctx, domain.SubjectTypeRole, roleCode, policyCode)
}

func (s *policyService) Attach(ctx context.Context, subType, subCode, policyCode string) error {
	return s.repo.Attach(ctx, subType, subCode, policyCode)
}

func (s *policyService) Detach(ctx context.Context, subType, subCode, policyCode string) error {
	return s.repo.Detach(ctx, subType, subCode, policyCode)
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

func (s *policyService) GetAttachedWithPagination(ctx context.Context, subType, subCode string, offset, limit int64, keyword string, policyType domain.PolicyType) ([]domain.Policy, int64, error) {
	return s.repo.GetAttachedWithPagination(ctx, subType, subCode, offset, limit, keyword, policyType)
}

func (s *policyService) ListAttachedPolicies(ctx context.Context, subType, subCode string, offset, limit int64, keyword string, policyType domain.PolicyType) ([]domain.Policy, int64, error) {
	ps, total, err := s.repo.GetAttachedWithPagination(ctx, subType, subCode, offset, limit, keyword, policyType)
	if err != nil {
		return nil, 0, err
	}

	// 填充授权数量统计
	if err = s.repo.FillAssignmentCounts(ctx, ps); err != nil {
		return nil, 0, err
	}

	return ps, total, nil
}

func (s *policyService) ListAssignments(ctx context.Context, offset, limit int64, subType string, keyword string, policyType uint8) ([]dao.PolicyAssignment, int64, error) {
	return s.repo.ListAssignments(ctx, offset, limit, subType, keyword, policyType)
}

func (s *policyService) BatchAttachPolicies(ctx context.Context, subjects []domain.Subject, policyCodes []string) (domain.BatchResult, error) {
	if len(subjects) == 0 || len(policyCodes) == 0 {
		return domain.BatchResult{}, nil
	}

	return s.repo.BatchAttach(ctx, subjects, policyCodes)
}

func (s *policyService) BatchDetachPolicies(ctx context.Context, assignments []domain.SubjectPolicyAssignment) (int64, error) {
	if len(assignments) == 0 {
		return 0, nil
	}

	return s.repo.BatchDetach(ctx, assignments)
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

func (s *policyService) DeletePolicy(ctx context.Context, code string) error {
	// 1. 获取策略元数据，判定类型
	p, err := s.repo.GetPolicyByCode(ctx, code)
	if err != nil {
		return err
	}

	// 1.1 禁止删除系统预置策略
	if p.Type == domain.SystemPolicy {
		return errs.ErrDeleteSystemPolicy
	}

	// 2. 引用计数校验：获取该策略当前的绑定数量
	ps := []domain.Policy{p}
	if err = s.repo.FillAssignmentCounts(ctx, ps); err != nil {
		return err
	}

	if ps[0].AssignmentCount > 0 {
		return errs.ErrPolicyInUse
	}

	return s.repo.DeletePolicy(ctx, code)
}

func (s *policyService) BatchDeletePolicies(ctx context.Context, codes []string) error {
	if len(codes) == 0 {
		return nil
	}

	// 1. 批量拉取策略详情
	ps, err := s.repo.ListByCodes(ctx, codes)
	if err != nil {
		return err
	}

	// 2. 批量校验
	// 2.1 检查是否存在系统策略
	for _, p := range ps {
		if p.Type == domain.SystemPolicy {
			return errs.ErrDeleteSystemPolicy
		}
	}

	// 2.2 检查引用计数
	if err = s.repo.FillAssignmentCounts(ctx, ps); err != nil {
		return err
	}
	for _, p := range ps {
		if p.AssignmentCount > 0 {
			return errs.ErrPolicyInUse
		}
	}

	// 3. 执行批量物理删除
	return s.repo.BatchDeletePolicies(ctx, codes)
}
