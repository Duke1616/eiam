package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// StateCache 这是一个通用的泛型缓存，用于处理“存入 -> 读取 -> 立即销毁”的临时状态逻辑
type StateCache[T any] struct {
	client redis.Cmdable
	prefix string
	ttl    time.Duration
}

func NewStateCache[T any](client redis.Cmdable, prefix string, ttl time.Duration) *StateCache[T] {
	return &StateCache[T]{
		client: client,
		prefix: prefix,
		ttl:    ttl,
	}
}

func (c *StateCache[T]) Set(ctx context.Context, key string, val T) error {
	data, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, c.key(key), data, c.ttl).Err()
}

func (c *StateCache[T]) Get(ctx context.Context, key string) (T, error) {
	k := c.key(key)
	val, err := c.client.Get(ctx, k).Result()
	if err != nil {
		var res T
		return res, err
	}
	// 读取后立即删除，确保一次性
	_ = c.client.Del(ctx, k)

	var res T
	err = json.Unmarshal([]byte(val), &res)
	return res, err
}

func (c *StateCache[T]) key(key string) string {
	return fmt.Sprintf("eiam:state:%s:%s", c.prefix, key)
}
