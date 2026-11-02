package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/samber/lo"
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
	// GetAttachedWithPagination 分页获取主体当前挂载的策略实体，支持关键词与类型过滤
	GetAttachedWithPagination(ctx context.Context, subType, subCode string, offset, limit int64, keyword string, policyType domain.PolicyType) ([]domain.Policy, int64, error)
	// ListByCodes 根据一组策略标识码获取策略详情列表
	ListByCodes(ctx context.Context, codes []string) ([]domain.Policy, error)
	// ListByTypes 按类型筛选策略详情列表
	ListByTypes(ctx context.Context, types []domain.PolicyType) ([]domain.Policy, error)
	// ListAssignments 分页获取策略分配关系
	ListAssignments(ctx context.Context, offset, limit int64, subType string, keyword string, policyType uint8) ([]dao.PolicyAssignment, int64, error)
	// BatchAttach 批量绑定策略到多个主体
	BatchAttach(ctx context.Context, subjects []domain.Subject, policyCodes []string) (domain.BatchResult, error)
	// BatchDetach 批量解绑策略
	BatchDetach(ctx context.Context, assignments []domain.SubjectPolicyAssignment) (int64, error)
	// FillAssignmentCounts 为策略列表填充授权计数值
	FillAssignmentCounts(ctx context.Context, ps []domain.Policy) error
	// DeletePolicy 删除策略实体
	DeletePolicy(ctx context.Context, code string) error
	// BatchDeletePolicies 批量删除策略实体
	BatchDeletePolicies(ctx context.Context, codes []string) error
}

type policyRepository struct {
	dao   dao.IPolicyDAO
	cache cache.IPolicyCache
}

func NewPolicyRepository(dao dao.IPolicyDAO, cache cache.IPolicyCache) IPolicyRepository {
	return &policyRepository{dao: dao, cache: cache}
}

func (r *policyRepository) CreatePolicy(ctx context.Context, p domain.Policy) (int64, error) {
	return r.dao.Insert(ctx, r.toDAO(p))
}

func (r *policyRepository) GetPolicyByCode(ctx context.Context, code string) (domain.Policy, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	if p, hit, err := r.cache.GetPolicyByCode(ctx, tid, code); err == nil && hit {
		return p, nil
	}

	p, err := r.dao.GetByCode(ctx, code)
	if err != nil {
		return domain.Policy{}, err
	}
	res := r.toDomain(p)
	_ = r.cache.SetPolicyByCode(ctx, tid, code, res)
	return res, nil
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

	return lo.Map(ps, func(src dao.Policy, _ int) domain.Policy {
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

	return lo.Map(ps, func(src dao.Policy, _ int) domain.Policy {
		return r.toDomain(src)
	}), total, nil
}

func (r *policyRepository) UpdatePolicy(ctx context.Context, p domain.Policy) error {
	err := r.dao.Update(ctx, r.toDAO(p))
	if err == nil && r.cache != nil {
		tid := ctxutil.GetTenantID(ctx).Int64()
		_ = r.cache.DeletePolicyByCode(ctx, tid, p.Code)
	}
	return err
}

func (r *policyRepository) Attach(ctx context.Context, subType, subCode, policyCode string) error {
	err := r.dao.Bind(ctx, subType, subCode, policyCode)
	if err == nil && r.cache != nil {
		tid := ctxutil.GetTenantID(ctx).Int64()
		_ = r.cache.DeleteAttached(ctx, tid, subType, subCode)
	}
	return err
}

func (r *policyRepository) Detach(ctx context.Context, subType, subCode, policyCode string) error {
	err := r.dao.Unbind(ctx, subType, subCode, policyCode)
	if err == nil && r.cache != nil {
		tid := ctxutil.GetTenantID(ctx).Int64()
		_ = r.cache.DeleteAttached(ctx, tid, subType, subCode)
	}
	return err
}

func (r *policyRepository) GetAttached(ctx context.Context, subType, subCode string) ([]domain.Policy, error) {
	sub := domain.Subject{Type: subType, ID: subCode}
	m, err := r.GetAttachedBySubjects(ctx, []domain.Subject{sub})
	if err != nil {
		return nil, err
	}
	return m[sub.URN()], nil
}

func (r *policyRepository) GetAttachedBySubjects(ctx context.Context, subjects []domain.Subject) (map[string][]domain.Policy, error) {
	if len(subjects) == 0 {
		return nil, nil
	}

	tid := ctxutil.GetTenantID(ctx).Int64()

	// 1. 过滤非法主体并去重
	validSubjects := lo.UniqBy(lo.Filter(subjects, func(s domain.Subject, _ int) bool {
		return s.Type != "" && s.ID != ""
	}), func(s domain.Subject) string {
		return s.URN()
	})

	subjectCodesMap := make(map[string][]string, len(validSubjects))
	var missingSubjects []domain.Subject

	// 2. 第一阶段：从主体挂载关系缓存中尝试获取 codes
	if r.cache != nil {
		for _, sub := range validSubjects {
			codes, hit, err := r.cache.GetAttachedCodes(ctx, tid, sub.Type, sub.ID)
			if err == nil && hit {
				subjectCodesMap[sub.URN()] = codes
			} else {
				missingSubjects = append(missingSubjects, sub)
			}
		}
	} else {
		missingSubjects = validSubjects
	}

	// 3. 对未命中主体挂载缓存的，从数据库关联表拉取并回填缓存
	if len(missingSubjects) > 0 {
		assignments, err := r.dao.GetCodesBySubjects(ctx, missingSubjects)
		if err != nil {
			return nil, err
		}

		assignmentsByURN := lo.GroupBy(assignments, func(a dao.PolicyAssignment) string {
			return a.SubType + ":" + a.SubCode
		})

		for _, sub := range missingSubjects {
			urn := sub.URN()
			codes := lo.Map(assignmentsByURN[urn], func(a dao.PolicyAssignment, _ int) string {
				return a.PolicyCode
			})
			subjectCodesMap[urn] = codes

			// 回填挂载关系缓存 (空切片防穿透)
			if r.cache != nil {
				_ = r.cache.SetAttachedCodes(ctx, tid, sub.Type, sub.ID, codes)
			}
		}
	}

	// 4. 第二阶段：聚合所有主体关联的去重策略 Codes，批量拉取策略详情
	allCodes := lo.Uniq(lo.Flatten(lo.Values(subjectCodesMap)))
	if len(allCodes) == 0 {
		return map[string][]domain.Policy{}, nil
	}

	policies, err := r.getPoliciesByCodes(ctx, tid, allCodes)
	if err != nil {
		return nil, err
	}

	policyMap := lo.SliceToMap(policies, func(p domain.Policy) (string, domain.Policy) {
		return p.Code, p
	})

	// 5. 第三阶段：将策略实体映射组装回各个主体
	result := make(map[string][]domain.Policy, len(subjectCodesMap))
	for urn, codes := range subjectCodesMap {
		if len(codes) == 0 {
			continue
		}
		ps := lo.FilterMap(codes, func(code string, _ int) (domain.Policy, bool) {
			p, ok := policyMap[code]
			return p, ok
		})
		if len(ps) > 0 {
			result[urn] = ps
		}
	}

	return result, nil
}

// getPoliciesByCodes 批量获取策略详情 (优先查详情缓存，缺失部分批量查库并回填)
func (r *policyRepository) getPoliciesByCodes(ctx context.Context, tid int64, codes []string) ([]domain.Policy, error) {
	if len(codes) == 0 {
		return nil, nil
	}

	uniqCodes := lo.Uniq(codes)
	var (
		hitMap       map[string]domain.Policy
		missingCodes []string
		err          error
	)

	if r.cache != nil {
		hitMap, missingCodes, err = r.cache.GetPoliciesByCodes(ctx, tid, uniqCodes)
		if err != nil {
			missingCodes = uniqCodes
			hitMap = make(map[string]domain.Policy)
		}
	} else {
		missingCodes = uniqCodes
		hitMap = make(map[string]domain.Policy)
	}

	// 针对未命中详情缓存的策略，从数据库批量查出并回填缓存
	if len(missingCodes) > 0 {
		dbPolicies, err := r.ListByCodes(ctx, missingCodes)
		if err != nil {
			return nil, err
		}
		for _, p := range dbPolicies {
			hitMap[p.Code] = p
		}
		if r.cache != nil {
			_ = r.cache.SetPolicies(ctx, tid, dbPolicies)
		}
	}

	// 保持请求 codes 顺序提取策略实体
	return lo.FilterMap(codes, func(code string, _ int) (domain.Policy, bool) {
		p, ok := hitMap[code]
		return p, ok
	}), nil
}

func (r *policyRepository) GetAttachedWithPagination(ctx context.Context, subType, subCode string, offset, limit int64, keyword string, policyType domain.PolicyType) ([]domain.Policy, int64, error) {
	// 直接调用联表过滤 DAO
	ps, total, err := r.dao.GetAttachedPoliciesWithFilter(ctx, subType, subCode, offset, limit, keyword, uint8(policyType))
	if err != nil || total == 0 {
		return nil, total, err
	}

	return lo.Map(ps, func(src dao.Policy, _ int) domain.Policy {
		return r.toDomain(src)
	}), total, nil
}

func (r *policyRepository) ListByCodes(ctx context.Context, codes []string) ([]domain.Policy, error) {
	ps, err := r.dao.GetByCodes(ctx, codes)
	return lo.Map(ps, func(p dao.Policy, _ int) domain.Policy {
		return r.toDomain(p)
	}), err
}

func (r *policyRepository) ListByTypes(ctx context.Context, types []domain.PolicyType) ([]domain.Policy, error) {
	ps, err := r.dao.GetByTypes(ctx, types)
	return lo.Map(ps, func(p dao.Policy, _ int) domain.Policy {
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

func (r *policyRepository) ListAssignments(ctx context.Context, offset, limit int64, subType string, keyword string, policyType uint8) ([]dao.PolicyAssignment, int64, error) {
	return r.dao.ListAssignments(ctx, offset, limit, subType, keyword, policyType)
}

const buildBatchSize = 1000

func (r *policyRepository) BatchAttach(ctx context.Context, subjects []domain.Subject, policyCodes []string) (domain.BatchResult, error) {
	if len(subjects) == 0 || len(policyCodes) == 0 {
		return domain.BatchResult{}, nil
	}

	// 1. 笛卡尔积组装待绑定的分配关系列表
	allAssignments := lo.FlatMap(subjects, func(sub domain.Subject, _ int) []dao.PolicyAssignment {
		return lo.Map(policyCodes, func(code string, _ int) dao.PolicyAssignment {
			return dao.PolicyAssignment{
				SubType:    sub.Type,
				SubCode:    sub.ID,
				PolicyCode: code,
			}
		})
	})

	var res domain.BatchResult
	// 2. 分批写入数据库，避免超出 SQL 占位符限制或导致事务锁膨胀
	for _, chunk := range lo.Chunk(allAssignments, buildBatchSize) {
		daoRes, err := r.dao.BatchBind(ctx, chunk)
		if err != nil {
			return res, err
		}
		res.Total += daoRes.Total
		res.Inserted += daoRes.Inserted
		res.Ignored += daoRes.Ignored
	}

	// 3. 若有实际插入产生，精准失效受影响主体的挂载缓存
	if res.Inserted > 0 && r.cache != nil {
		tid := ctxutil.GetTenantID(ctx).Int64()
		_ = r.cache.DeleteAttachedBySubjects(ctx, tid, subjects)
	}

	return res, nil
}

func (r *policyRepository) BatchDetach(ctx context.Context, assignments []domain.SubjectPolicyAssignment) (int64, error) {
	if len(assignments) == 0 {
		return 0, nil
	}

	daoAssignments := lo.Map(assignments, func(a domain.SubjectPolicyAssignment, _ int) dao.PolicyAssignment {
		return dao.PolicyAssignment{
			SubType:    a.SubType,
			SubCode:    a.SubCode,
			PolicyCode: a.PolicyCode,
		}
	})

	var totalAffected int64
	// 分批执行解绑，控制每次删除的记录数
	for _, chunk := range lo.Chunk(daoAssignments, buildBatchSize) {
		affected, err := r.dao.BatchUnbind(ctx, chunk)
		if err != nil {
			return totalAffected, err
		}
		totalAffected += affected
	}

	// 若有删除生效，精准失效受影响主体的挂载缓存（去重后再失效）
	if totalAffected > 0 && r.cache != nil {
		tid := ctxutil.GetTenantID(ctx).Int64()
		affectedSubjects := lo.UniqBy(lo.Map(assignments, func(a domain.SubjectPolicyAssignment, _ int) domain.Subject {
			return domain.Subject{
				Type: a.SubType,
				ID:   a.SubCode,
			}
		}), func(s domain.Subject) string {
			return s.Type + ":" + s.ID
		})
		_ = r.cache.DeleteAttachedBySubjects(ctx, tid, affectedSubjects)
	}

	return totalAffected, nil
}

func (r *policyRepository) FillAssignmentCounts(ctx context.Context, ps []domain.Policy) error {
	if len(ps) == 0 {
		return nil
	}
	codes := lo.Map(ps, func(p domain.Policy, _ int) string {
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

func (r *policyRepository) DeletePolicy(ctx context.Context, code string) error {
	err := r.dao.Delete(ctx, code)
	if err == nil && r.cache != nil {
		tid := ctxutil.GetTenantID(ctx).Int64()
		_ = r.cache.DeletePolicyByCode(ctx, tid, code)
	}
	return err
}

func (r *policyRepository) BatchDeletePolicies(ctx context.Context, codes []string) error {
	err := r.dao.BatchDelete(ctx, codes)
	if err == nil && r.cache != nil {
		tid := ctxutil.GetTenantID(ctx).Int64()
		_ = r.cache.DeletePoliciesByCodes(ctx, tid, codes)
	}
	return err
}
