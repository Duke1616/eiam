package searcher

import (
	"context"
	"sync"

	"golang.org/x/sync/errgroup"
)

// Subject 契约定义的主体视图结构
type Subject struct {
	Type string
	ID   string
	Name string
	Desc string
}

// SubjectProvider 全域主体搜索提供者契约
// 用于规范各领域（用户、角色等）在治理中心统一搜索行为的标准化接口
type SubjectProvider interface {
	// SearchSubjects 执行特定领域的关键词搜索，仅返回主体数据结果集
	// @param keyword 搜索关键字，通常匹配名称或系统标识
	// @param offset 偏移起始位置
	// @param limit 返回数量上限
	SearchSubjects(ctx context.Context, keyword string, offset, limit int64) ([]Subject, error)

	// CountSubjects 获取符合关键词搜索条件的主体总数
	// 用于支持前端分页计算以及聚合搜索时的偏移区间定位
	CountSubjects(ctx context.Context, keyword string) (int64, error)

	// SupportType 返回该提供者所支持的主体类型标识（如 "user", "role"）
	// 用于注册中心进行精确路由分发
	SupportType() string
}

// SubjectAdapter 适配器
type SubjectAdapter[T any] struct {
	supportType string
	searchFn    func(ctx context.Context, keyword string, offset, limit int64) ([]T, error)
	countFn     func(ctx context.Context, keyword string) (int64, error)
	mapper      func(T) Subject
}

func NewSubjectAdapter[T any](
	supportType string,
	search func(ctx context.Context, keyword string, offset, limit int64) ([]T, error),
	count func(ctx context.Context, keyword string) (int64, error),
	mapper func(T) Subject,
) *SubjectAdapter[T] {
	return &SubjectAdapter[T]{
		supportType: supportType,
		searchFn:    search,
		countFn:     count,
		mapper:      mapper,
	}
}

func (a *SubjectAdapter[T]) SearchSubjects(ctx context.Context, keyword string, offset, limit int64) ([]Subject, error) {
	ts, err := a.searchFn(ctx, keyword, offset, limit)
	if err != nil {
		return nil, err
	}
	res := make([]Subject, len(ts))
	for i, t := range ts {
		res[i] = a.mapper(t)
	}
	return res, nil
}

func (a *SubjectAdapter[T]) CountSubjects(ctx context.Context, keyword string) (int64, error) {
	return a.countFn(ctx, keyword)
}

func (a *SubjectAdapter[T]) SupportType() string { return a.supportType }

// ISubjectRegistry 治理能力注册中心接口
type ISubjectRegistry interface {
	SubjectProvider
	// Register 注册提供者
	Register(ps ...SubjectProvider)
	// Route 根据类型获取提供者 (支持单类型或全聚合)
	Route(subType string) SubjectProvider
}

// subjectRegistry 注册中心实现 (组合模式)
type subjectRegistry struct {
	mu        sync.RWMutex
	providers []SubjectProvider
	typeMap   map[string]SubjectProvider
}

func NewSubjectRegistry(ps ...SubjectProvider) ISubjectRegistry {
	reg := &subjectRegistry{
		typeMap: make(map[string]SubjectProvider),
	}
	reg.Register(ps...)
	return reg
}

func (r *subjectRegistry) Register(ps ...SubjectProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range ps {
		r.providers = append(r.providers, p)
		r.typeMap[p.SupportType()] = p
	}
}

func (r *subjectRegistry) Route(subType string) SubjectProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, ok := r.typeMap[subType]; ok {
		return p
	}
	return r
}

func (r *subjectRegistry) SearchSubjects(ctx context.Context, keyword string, offset, limit int64) ([]Subject, error) {
	r.mu.RLock()
	ps := r.providers
	r.mu.RUnlock()

	var res []Subject
	totals := make([]int64, len(ps))

	// 并行获取各领域的 Total，用于偏移计算
	var eg errgroup.Group
	for i, p := range ps {
		idx, provider := i, p
		eg.Go(func() error {
			total, err := provider.CountSubjects(ctx, keyword)
			if err != nil {
				return err
			}
			totals[idx] = total
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}

	// 顺序偏移算法执行查询
	currentOffset := offset
	for i, p := range ps {
		pTotal := totals[i]
		if int64(len(res)) < limit && currentOffset < pTotal {
			pLimit := limit - int64(len(res))
			pSubjects, err := p.SearchSubjects(ctx, keyword, currentOffset, pLimit)
			if err != nil {
				return nil, err
			}
			res = append(res, pSubjects...)
			currentOffset = 0
		} else {
			currentOffset = max(0, currentOffset-pTotal)
		}
	}
	return res, nil
}

func (r *subjectRegistry) CountSubjects(ctx context.Context, keyword string) (int64, error) {
	r.mu.RLock()
	ps := r.providers
	r.mu.RUnlock()

	var (
		total int64
		eg    errgroup.Group
		mu    sync.Mutex
	)
	for _, p := range ps {
		p := p
		eg.Go(func() error {
			count, err := p.CountSubjects(ctx, keyword)
			if err != nil {
				return err
			}
			mu.Lock()
			total += count
			mu.Unlock()
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return 0, err
	}
	return total, nil
}

func (r *subjectRegistry) SupportType() string { return "aggregated" }
