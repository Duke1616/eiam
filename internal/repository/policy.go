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
	// UpdatePolicy 更新权限策略
	UpdatePolicy(ctx context.Context, p domain.Policy) error
	// AttachPolicyToRole 将策略挂载到角色上
	AttachPolicyToRole(ctx context.Context, roleCode, polyCode string) error
	// DetachPolicyFromRole 从角色上移除已挂载的策略
	DetachPolicyFromRole(ctx context.Context, roleCode, polyCode string) error
	// GetAttachedPolicies 获取角色当前挂载的所有托管策略实体
	GetAttachedPolicies(ctx context.Context, roleCode string) ([]domain.Policy, error)
	// GetAttachedPoliciesByCodes 批量获取多个角色当前挂载的所有托管策略实体
	GetAttachedPoliciesByCodes(ctx context.Context, roleCodes []string) (map[string][]domain.Policy, error)
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
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		var err error
		ps, err = r.dao.List(ctx, offset, limit)
		return err
	})

	eg.Go(func() error {
		var err error
		total, err = r.dao.Count(ctx)
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

func (r *policyRepository) AttachPolicyToRole(ctx context.Context, roleCode, polyCode string) error {
	return r.dao.BindToRole(ctx, roleCode, polyCode)
}

func (r *policyRepository) DetachPolicyFromRole(ctx context.Context, roleCode, polyCode string) error {
	return r.dao.UnbindFromRole(ctx, roleCode, polyCode)
}

func (r *policyRepository) GetAttachedPolicies(ctx context.Context, roleCode string) ([]domain.Policy, error) {
	// 1. 先从关联表拉取所有的策略代码
	codes, err := r.dao.GetCodesByRole(ctx, roleCode)
	if err != nil || len(codes) == 0 {
		return nil, err
	}

	// 2. 批量拉取策略详情
	ps, err := r.dao.GetByCodes(ctx, codes)
	return slice.Map(ps, func(idx int, p dao.Policy) domain.Policy {
		return r.toDomain(p)
	}), err
}

func (r *policyRepository) GetAttachedPoliciesByCodes(ctx context.Context, roleCodes []string) (map[string][]domain.Policy, error) {
	// 1. 获取所有角色关联的策略代码
	attachments, err := r.dao.GetCodesByRoleCodes(ctx, roleCodes)
	if err != nil || len(attachments) == 0 {
		return nil, err
	}

	// 2. 提取并去重策略代码 (多对多关联中，多个角色可能指向同一个策略)
	policyCodeSet := make(map[string]struct{})
	for i := range attachments {
		policyCodeSet[attachments[i].PolyCode] = struct{}{}
	}
	policyCodes := make([]string, 0, len(policyCodeSet))
	for code := range policyCodeSet {
		policyCodes = append(policyCodes, code)
	}

	// 3. 批量获取策略详情
	ps, err := r.dao.GetByCodes(ctx, policyCodes)
	if err != nil {
		return nil, err
	}

	// 4. 构建策略代码到领域模型的映射索引
	policyMap := make(map[string]domain.Policy, len(ps))
	for i := range ps {
		policyMap[ps[i].Code] = r.toDomain(ps[i])
	}

	// 5. 构建角色代码到策略列表的最终映射
	roleToPolicies := make(map[string][]domain.Policy, len(roleCodes))
	for i := range attachments {
		roleCode := attachments[i].RoleCode
		polyCode := attachments[i].PolyCode
		if p, ok := policyMap[polyCode]; ok {
			roleToPolicies[roleCode] = append(roleToPolicies[roleCode], p)
		}
	}

	return roleToPolicies, nil
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
