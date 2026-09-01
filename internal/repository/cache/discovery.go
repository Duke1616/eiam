package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// IDiscoveryCache 资产发现分布式缓存与并发控制接口
type IDiscoveryCache interface {
	// GetLastHash 获取服务已同步的最新资产 Hash
	GetLastHash(ctx context.Context, service string) (string, error)
	// SetLastHash 设置服务已同步的最新资产 Hash
	SetLastHash(ctx context.Context, service, hash string) error
	// TryLockSync 尝试获取微服务对账分布式锁，通过 owner 标识防误删 (默认过期 15s)
	TryLockSync(ctx context.Context, service, owner string, expiration time.Duration) (bool, error)
	// UnlockSync 释放微服务对账分布式锁，仅当锁属于指定 owner 时才删除
	UnlockSync(ctx context.Context, service, owner string) error
}

var (
	// luaReleaseLock 原子释放分布式锁脚本：仅在值匹配 owner 时删除
	luaReleaseLock = redis.NewScript(`
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`)
)

type discoveryCache struct {
	client redis.Cmdable
}

// NewDiscoveryCache 构建资产发现分布式缓存实例
func NewDiscoveryCache(client redis.Cmdable) IDiscoveryCache {
	return &discoveryCache{client: client}
}

func (c *discoveryCache) hashKey(service string) string {
	return fmt.Sprintf("eiam:discovery:hash:%s", service)
}

func (c *discoveryCache) lockKey(service string) string {
	return fmt.Sprintf("eiam:discovery:lock:%s", service)
}

func (c *discoveryCache) GetLastHash(ctx context.Context, service string) (string, error) {
	val, err := c.client.Get(ctx, c.hashKey(service)).Result()
	if err == redis.Nil {
		return "", nil
	}
	return val, err
}

func (c *discoveryCache) SetLastHash(ctx context.Context, service, hash string) error {
	// 永久有效或长期保存，直到下次版本变更覆盖
	return c.client.Set(ctx, c.hashKey(service), hash, 0).Err()
}

func (c *discoveryCache) TryLockSync(ctx context.Context, service, owner string, expiration time.Duration) (bool, error) {
	if expiration <= 0 {
		expiration = 15 * time.Second
	}
	return c.client.SetNX(ctx, c.lockKey(service), owner, expiration).Result()
}

func (c *discoveryCache) UnlockSync(ctx context.Context, service, owner string) error {
	return luaReleaseLock.Run(ctx, c.client, []string{c.lockKey(service)}, owner).Err()
}

