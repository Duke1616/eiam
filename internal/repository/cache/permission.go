package cache

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	//go:embed lua/perm_invalidate_parents.lua
	luaInvalidateParents string
)

// IPermissionCache 权限与物理资源绑定映射缓存接口
//
//go:generate mockgen -package=cachemocks -destination=./mocks/permission.mock.go github.com/Duke1616/eiam/internal/repository/cache IPermissionCache
type IPermissionCache interface {
	// GetCodesByResource 根据物理资源 URN 获取绑定的功能权限码列表；未命中返回 ErrCacheNotFound
	GetCodesByResource(ctx context.Context, resURN string) ([]string, error)
	// SetCodesByResource 缓存资源 URN 对应的权限码映射
	SetCodesByResource(ctx context.Context, resURN string, codes []string) error
	// DeleteCodesByResources 批量清空指定资源 URN 的缓存
	DeleteCodesByResources(ctx context.Context, resURNs []string) error

	// GetParentsByNeeds 获取满足 needs 依赖的父级权限码列表；未命中返回 ErrCacheNotFound
	GetParentsByNeeds(ctx context.Context, codes []string) ([]string, error)
	// SetParentsByNeeds 缓存满足 needs 依赖的父级权限码列表
	SetParentsByNeeds(ctx context.Context, codes []string, parents []string) error
	// ClearParentCodes 原子清空所有权限拓扑依赖缓存
	ClearParentCodes(ctx context.Context) error
}

type permissionCache struct {
	client redis.Cmdable
	ttl    time.Duration
}

// NewPermissionCache 创建权限仓库缓存实例
func NewPermissionCache(client redis.Cmdable) IPermissionCache {
	return &permissionCache{
		client: client,
		ttl:    2 * time.Hour,
	}
}

func (c *permissionCache) resCodesKey(resURN string) string {
	return fmt.Sprintf("eiam:perm:res_codes:%s", resURN)
}

func (c *permissionCache) GetCodesByResource(ctx context.Context, resURN string) ([]string, error) {
	key := c.resCodesKey(resURN)
	val, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrCacheNotFound
		}
		return nil, err
	}

	var codes []string
	if err = json.Unmarshal(val, &codes); err != nil {
		return nil, fmt.Errorf("反序列化权限映射缓存失败: %w", err)
	}

	return codes, nil
}

func (c *permissionCache) SetCodesByResource(ctx context.Context, resURN string, codes []string) error {
	data, err := json.Marshal(codes)
	if err != nil {
		return fmt.Errorf("序列化权限映射缓存失败: %w", err)
	}

	key := c.resCodesKey(resURN)
	ttl := c.jitterTTL(c.ttl)

	return c.client.Set(ctx, key, data, ttl).Err()
}

func (c *permissionCache) DeleteCodesByResources(ctx context.Context, resURNs []string) error {
	if len(resURNs) == 0 {
		return nil
	}

	keys := make([]string, len(resURNs))
	for i, urn := range resURNs {
		keys[i] = c.resCodesKey(urn)
	}

	return c.client.Del(ctx, keys...).Err()
}

func (c *permissionCache) parentsKey(codes []string) string {
	sorted := slices.Clone(codes)
	slices.Sort(sorted)
	return fmt.Sprintf("eiam:perm:parents:%s", strings.Join(sorted, ","))
}

func (c *permissionCache) parentKeysSet() string {
	return "eiam:perm:parent_keys"
}

func (c *permissionCache) GetParentsByNeeds(ctx context.Context, codes []string) ([]string, error) {
	key := c.parentsKey(codes)
	val, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrCacheNotFound
		}
		return nil, err
	}

	var parents []string
	if err = json.Unmarshal(val, &parents); err != nil {
		return nil, fmt.Errorf("反序列化权限拓扑缓存失败: %w", err)
	}

	return parents, nil
}

func (c *permissionCache) SetParentsByNeeds(ctx context.Context, codes []string, parents []string) error {
	data, err := json.Marshal(parents)
	if err != nil {
		return fmt.Errorf("序列化权限拓扑缓存失败: %w", err)
	}

	key := c.parentsKey(codes)
	setKey := c.parentKeysSet()
	ttl := c.jitterTTL(c.ttl)

	pipe := c.client.Pipeline()
	pipe.Set(ctx, key, data, ttl)
	pipe.SAdd(ctx, setKey, key)
	pipe.Expire(ctx, setKey, ttl+time.Hour)
	_, err = pipe.Exec(ctx)
	return err
}

func (c *permissionCache) ClearParentCodes(ctx context.Context) error {
	setKey := c.parentKeysSet()
	return c.client.Eval(ctx, luaInvalidateParents, []string{setKey}).Err()
}

// jitterTTL 为过期时间增加 ±10% 随机抖动，避免缓存雪崩
func (c *permissionCache) jitterTTL(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	jitterRange := int64(base / 10)
	if jitterRange <= 0 {
		return base
	}
	jitter := time.Duration(rand.Int63n(jitterRange))
	if rand.Intn(2) == 0 {
		return base + jitter
	}
	return base - jitter
}
