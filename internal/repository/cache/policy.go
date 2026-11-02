package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/redis/go-redis/v9"
	"github.com/samber/lo"
)

// IPolicyCache 托管策略与主体绑定关系的仓储层专属缓存接口
//
//go:generate mockgen -package=cachemocks -destination=./mocks/policy.mock.go github.com/Duke1616/eiam/internal/repository/cache IPolicyCache
type IPolicyCache interface {
	// GetPolicyByCode 获取指定租户下的单条策略实体详情；hit 为 true 表示命中缓存
	GetPolicyByCode(ctx context.Context, tid int64, code string) (domain.Policy, bool, error)
	// SetPolicyByCode 缓存指定租户下的单条策略实体详情
	SetPolicyByCode(ctx context.Context, tid int64, code string, p domain.Policy) error
	// DeletePolicyByCode 驱逐单条策略实体详情缓存
	DeletePolicyByCode(ctx context.Context, tid int64, code string) error
	// DeletePoliciesByCodes 批量驱逐策略实体详情缓存
	DeletePoliciesByCodes(ctx context.Context, tid int64, codes []string) error

	// GetPoliciesByCodes 批量获取策略详情；返回命中字典与未命中代码切片
	GetPoliciesByCodes(ctx context.Context, tid int64, codes []string) (map[string]domain.Policy, []string, error)
	// SetPolicies 批量回写策略详情缓存 (基于 Pipeline)
	SetPolicies(ctx context.Context, tid int64, policies []domain.Policy) error

	// GetAttachedCodes 获取主体挂载的策略代码列表；hit 为 true 表示命中 (支持空切片防穿透)
	GetAttachedCodes(ctx context.Context, tid int64, subType, subCode string) ([]string, bool, error)
	// SetAttachedCodes 缓存主体挂载的策略代码列表
	SetAttachedCodes(ctx context.Context, tid int64, subType, subCode string, codes []string) error
	// DeleteAttached 驱逐特定主体的策略挂载列表缓存
	DeleteAttached(ctx context.Context, tid int64, subType, subCode string) error
	// DeleteAttachedBySubjects 批量驱逐多个主体的策略挂载列表缓存
	DeleteAttachedBySubjects(ctx context.Context, tid int64, subjects []domain.Subject) error
}

type policyCache struct {
	client redis.Cmdable
	entity *EntityCache[domain.Policy]
}

// NewPolicyCache 创建策略仓储缓存实例
func NewPolicyCache(client redis.Cmdable) IPolicyCache {
	return &policyCache{
		client: client,
		entity: NewEntityCache[domain.Policy](
			client,
			"policy:detail",
			30*time.Minute,
			func(p domain.Policy) string { return p.Code },
		),
	}
}

func (c *policyCache) attachedCodesKey(tid int64, subType, subCode string) string {
	return fmt.Sprintf("eiam:policy:attached_codes:%d:%s:%s", tid, subType, subCode)
}

func (c *policyCache) GetPolicyByCode(ctx context.Context, tid int64, code string) (domain.Policy, bool, error) {
	return c.entity.Get(ctx, tid, code)
}

func (c *policyCache) SetPolicyByCode(ctx context.Context, tid int64, code string, p domain.Policy) error {
	return c.entity.Set(ctx, tid, code, p)
}

func (c *policyCache) DeletePolicyByCode(ctx context.Context, tid int64, code string) error {
	return c.entity.Delete(ctx, tid, code)
}

func (c *policyCache) DeletePoliciesByCodes(ctx context.Context, tid int64, codes []string) error {
	return c.entity.DeleteMulti(ctx, tid, codes)
}

func (c *policyCache) GetPoliciesByCodes(ctx context.Context, tid int64, codes []string) (map[string]domain.Policy, []string, error) {
	return c.entity.GetMulti(ctx, tid, codes)
}

func (c *policyCache) SetPolicies(ctx context.Context, tid int64, policies []domain.Policy) error {
	return c.entity.SetMulti(ctx, tid, policies)
}

func (c *policyCache) GetAttachedCodes(ctx context.Context, tid int64, subType, subCode string) ([]string, bool, error) {
	key := c.attachedCodesKey(tid, subType, subCode)
	val, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, false, nil
		}
		return nil, false, err
	}

	var codes []string
	if err = json.Unmarshal(val, &codes); err != nil {
		return nil, false, fmt.Errorf("反序列化主体挂载代码缓存失败: %w", err)
	}

	// 命中缓存 (包含空切片 []，实现防御性防缓存穿透)
	return codes, true, nil
}

func (c *policyCache) SetAttachedCodes(ctx context.Context, tid int64, subType, subCode string, codes []string) error {
	if codes == nil {
		codes = []string{}
	}

	data, err := json.Marshal(codes)
	if err != nil {
		return fmt.Errorf("序列化主体挂载代码缓存失败: %w", err)
	}

	key := c.attachedCodesKey(tid, subType, subCode)
	return c.client.Set(ctx, key, data, c.entity.JitterTTL()).Err()
}

func (c *policyCache) DeleteAttached(ctx context.Context, tid int64, subType, subCode string) error {
	key := c.attachedCodesKey(tid, subType, subCode)
	return c.client.Del(ctx, key).Err()
}

func (c *policyCache) DeleteAttachedBySubjects(ctx context.Context, tid int64, subjects []domain.Subject) error {
	keys := lo.Uniq(lo.FilterMap(subjects, func(sub domain.Subject, _ int) (string, bool) {
		if sub.Type == "" || sub.ID == "" {
			return "", false
		}
		return c.attachedCodesKey(tid, sub.Type, sub.ID), true
	}))
	if len(keys) == 0 {
		return nil
	}
	return c.client.Del(ctx, keys...).Err()
}
