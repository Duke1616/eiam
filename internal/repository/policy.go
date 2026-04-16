package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/ecodeclub/ekit/slice"
	"golang.org/x/sync/errgroup"
)

// IPolicyRepository 策略仓储接口：封装策略实体的持久化与关联逻辑
type IPolicyRepository interface {
	// CreatePolicy 创建一个可全局复用的托管策略
	CreatePolicy(ctx context.Context, p domain.Policy) (int64, error)
	// GetPolicyByCode 按标识码检索策略实体
	GetPolicyByCode(ctx context.Context, code string) (domain.Policy, error)
	// ListPolicies 分页获取策略列表
	ListPolicies(ctx context.Context, offset, limit int64) ([]domain.Policy, int64, error)
	// SearchPolicies 关键词与类型过滤获取策略列表
	SearchPolicies(ctx context.Context, offset, limit int64, keyword string, policyType domain.PolicyType) ([]domain.Policy, int64, error)
	// UpdatePolicy 更新权限策略
	UpdatePolicy(ctx context.Context, p domain.Policy) error
	// Attach 将策略挂载到主体上 (用户或角色)
	Attach(ctx context.Context, subType, subCode, policyCode string) error
	// Detach 从主体上移除已挂载的策略
	Detach(ctx context.Context, subType, subCode, policyCode string) error
	// GetAttached 获取主体当前挂载的所有托管策略实体
	GetAttached(ctx context.Context, subType, subCode string) ([]domain.Policy, error)
	// GetAttachedBySubjects 批量获取多个主体当前挂载的所有托管策略实体映射 (如用户+其所属的所有角色)
	GetAttachedBySubjects(ctx context.Context, subjects []domain.Subject) (map[string][]domain.Policy, error)
	// ListByCodes 根据一组策略标识码获取策略详情列表
	ListByCodes(ctx context.Context, codes []string) ([]domain.Policy, error)
	// ListByTypes 按类型筛选策略详情列表
	ListByTypes(ctx context.Context, types []domain.PolicyType) ([]domain.Policy, error)
	// ListAssignments 分页获取策略分配关系
	ListAssignments(ctx context.Context, offset, limit int64, subType string, keyword string) ([]dao.PolicyAssignment, int64, error)
	// BatchAttach 批量绑定策略到多个主体
	BatchAttach(ctx context.Context, subjects []domain.Subject, policyCodes []string) (domain.BatchResult, error)
	// FillAssignmentCounts 为策略列表填充授权计数值
	FillAssignmentCounts(ctx context.Context, ps []domain.Policy) error
}

type policyRepository struct {
	dao dao.IPolicyDAO
}

func NewPolicyRepository(dao dao.IPolicyDAO) IPolicyRepository {
	return &policyRepository{dao: dao}
}

func (r *policyRepository) CreatePolicy(ctx context.Context, p domain.Policy) (int64, error) {
	return r.dao.Insert(ctx, r.toDAO(p))
}

func (r *policyRepository) GetPolicyByCode(ctx context.Context, code string) (domain.Policy, error) {
	p, err := r.dao.GetByCode(ctx, code)
	return r.toDomain(p), err
}

func (r *policyRepository) ListPolicies(ctx context.Context, offset, limit int64) ([]domain.Policy, int64, error) {
	var (
		ps    []dao.Policy
		total int64
	)
	eg, gctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		var err error
		ps, err = r.dao.List(gctx, offset, limit)
		return err
	})

	eg.Go(func() error {
		var err error
		total, err = r.dao.Count(gctx)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	return slice.Map(ps, func(idx int, src dao.Policy) domain.Policy {
		return r.toDomain(src)
	}), total, nil
}

func (r *policyRepository) SearchPolicies(ctx context.Context, offset, limit int64, keyword string, policyType domain.PolicyType) ([]domain.Policy, int64, error) {
	var (
		ps    []dao.Policy
		total int64
	)
	eg, gctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		var err error
		ps, err = r.dao.Search(gctx, offset, limit, keyword, uint8(policyType))
		return err
	})

	eg.Go(func() error {
		var err error
		total, err = r.dao.CountBySearch(gctx, keyword, uint8(policyType))
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	return slice.Map(ps, func(idx int, src dao.Policy) domain.Policy {
		return r.toDomain(src)
	}), total, nil
}

func (r *policyRepository) UpdatePolicy(ctx context.Context, p domain.Policy) error {
	return r.dao.Update(ctx, r.toDAO(p))
}

func (r *policyRepository) Attach(ctx context.Context, subType, subCode, policyCode string) error {
	return r.dao.Bind(ctx, subType, subCode, policyCode)
}

func (r *policyRepository) Detach(ctx context.Context, subType, subCode, policyCode string) error {
	return r.dao.Unbind(ctx, subType, subCode, policyCode)
}

func (r *policyRepository) GetAttached(ctx context.Context, subType, subCode string) ([]domain.Policy, error) {
	// 1. 先从关联表拉取所有的策略代码
	codes, err := r.dao.GetCodesBySubject(ctx, subType, subCode)
	if err != nil || len(codes) == 0 {
		return nil, err
	}

	// 2. 批量拉取策略详情
	return r.ListByCodes(ctx, codes)
}

func (r *policyRepository) GetAttachedBySubjects(ctx context.Context, subjects []domain.Subject) (map[string][]domain.Policy, error) {
	// 1. 获取所有主体关联的策略代码
	assignments, err := r.dao.GetCodesBySubjects(ctx, subjects)
	if err != nil || len(assignments) == 0 {
		return nil, err
	}

	// 2. 提取并去重策略代码
	policyCodeSet := make(map[string]struct{})
	for i := range assignments {
		policyCodeSet[assignments[i].PolicyCode] = struct{}{}
	}
	policyCodes := make([]string, 0, len(policyCodeSet))
	for code := range policyCodeSet {
		policyCodes = append(policyCodes, code)
	}

	// 3. 批量获取策略详情
	ps, err := r.ListByCodes(ctx, policyCodes)
	if err != nil {
		return nil, err
	}

	// 4. 构建策略代码映射索引
	policyMap := make(map[string]domain.Policy, len(ps))
	for i := range ps {
		policyMap[ps[i].Code] = ps[i]
	}

	// 5. 构建主体 URN (如 role:admin) 到策略列表的最终映射
	result := make(map[string][]domain.Policy)
	for i := range assignments {
		// 这里使用 subType:subCode 作为 key
		urn := assignments[i].SubType + ":" + assignments[i].SubCode
		policyCode := assignments[i].PolicyCode
		if p, ok := policyMap[policyCode]; ok {
			result[urn] = append(result[urn], p)
		}
	}

	return result, nil
}

func (r *policyRepository) ListByCodes(ctx context.Context, codes []string) ([]domain.Policy, error) {
	ps, err := r.dao.GetByCodes(ctx, codes)
	return slice.Map(ps, func(idx int, p dao.Policy) domain.Policy {
		return r.toDomain(p)
	}), err
}

func (r *policyRepository) ListByTypes(ctx context.Context, types []domain.PolicyType) ([]domain.Policy, error) {
	ps, err := r.dao.GetByTypes(ctx, types)
	return slice.Map(ps, func(idx int, p dao.Policy) domain.Policy {
		return r.toDomain(p)
	}), err
}

func (r *policyRepository) toDomain(p dao.Policy) domain.Policy {
	return domain.Policy{
		ID:        p.Id,
		TenantID:  p.TenantId,
		Name:      p.Name,
		Code:      p.Code,
		Desc:      p.Desc,
		Type:      domain.PolicyType(p.Type),
		Statement: p.Document.Val,
		Ctime:     p.Ctime,
	}
}

func (r *policyRepository) toDAO(p domain.Policy) dao.Policy {
	return dao.Policy{
		Id:       p.ID,
		TenantId: p.TenantID,
		Name:     p.Name,
		Code:     p.Code,
		Desc:     p.Desc,
		Type:     uint8(p.Type),
		Document: sqlx.JSONColumn[[]domain.Statement]{
			Val:   p.Statement,
			Valid: true,
		},
	}
}

func (r *policyRepository) ListAssignments(ctx context.Context, offset, limit int64, subType string, keyword string) ([]dao.PolicyAssignment, int64, error) {
	return r.dao.ListAssignments(ctx, offset, limit, subType, keyword)
}

const buildBatchSize = 1000

func (r *policyRepository) BatchAttach(ctx context.Context, subjects []domain.Subject, policyCodes []string) (domain.BatchResult, error) {
	if len(subjects) == 0 || len(policyCodes) == 0 {
		return domain.BatchResult{}, nil
	}

	var res domain.BatchResult
	assignments := make([]dao.PolicyAssignment, 0, buildBatchSize)

	flush := func() error {
		if len(assignments) == 0 {
			return nil
		}
		daoRes, err := r.dao.BatchBind(ctx, assignments)
		if err != nil {
			return err
		}
		res.Total += daoRes.Total
		res.Inserted += daoRes.Inserted
		res.Ignored += daoRes.Ignored
		assignments = assignments[:0]
		return nil
	}

	for i := range subjects {
		for j := range policyCodes {
			assignments = append(assignments, dao.PolicyAssignment{
				SubType:    subjects[i].Type,
				SubCode:    subjects[i].ID,
				PolicyCode: policyCodes[j],
			})

			if len(assignments) >= buildBatchSize {
				if err := flush(); err != nil {
					return res, err
				}
			}
		}
	}

	if err := flush(); err != nil {
		return res, err
	}

	return res, nil
}

func (r *policyRepository) FillAssignmentCounts(ctx context.Context, ps []domain.Policy) error {
	if len(ps) == 0 {
		return nil
	}
	codes := slice.Map(ps, func(idx int, p domain.Policy) string {
		return p.Code
	})
	counts, err := r.dao.CountAssignmentsByPolicyCodes(ctx, codes)
	if err != nil {
		return err
	}
	for i := range ps {
		ps[i].AssignmentCount = counts[ps[i].Code]
	}
	return nil
}
