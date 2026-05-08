package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrCacheNotFound = redis.Nil
)

type IUserCache interface {
	IncFailedAttempts(ctx context.Context, username string, duration time.Duration) (int64, error)
	ClearFailedAttempts(ctx context.Context, username string) error
	SetLockout(ctx context.Context, username string, duration time.Duration) error
	IsLocked(ctx context.Context, username string) (bool, error)

	// SetBindState 存储临时绑定状态 (5分钟过期)
	SetBindState(ctx context.Context, token string, ident any) error
	// GetBindState 获取并删除临时绑定状态
	GetBindState(ctx context.Context, token string) (string, error)
}

type userCache struct {
	client redis.Cmdable
}

func NewUserCache(client redis.Cmdable) IUserCache {
	return &userCache{client: client}
}

func (c *userCache) IncFailedAttempts(ctx context.Context, username string, duration time.Duration) (int64, error) {
	key := c.failedAttemptsKey(username)
	pipe := c.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, duration)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

func (c *userCache) ClearFailedAttempts(ctx context.Context, username string) error {
	return c.client.Del(ctx, c.failedAttemptsKey(username)).Err()
}

func (c *userCache) SetLockout(ctx context.Context, username string, duration time.Duration) error {
	return c.client.Set(ctx, c.lockoutKey(username), "1", duration).Err()
}

func (c *userCache) IsLocked(ctx context.Context, username string) (bool, error) {
	res, err := c.client.Exists(ctx, c.lockoutKey(username)).Result()
	if err != nil {
		return false, err
	}
	return res > 0, nil
}

func (c *userCache) failedAttemptsKey(username string) string {
	return fmt.Sprintf("eiam:user:failed_attempts:%s", username)
}

func (c *userCache) lockoutKey(username string) string {
	return fmt.Sprintf("eiam:user:lockout:%s", username)
}

func (c *userCache) SetBindState(ctx context.Context, token string, ident any) error {
	data, err := json.Marshal(ident)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, c.bindKey(token), data, 5*time.Minute).Err()
}

func (c *userCache) GetBindState(ctx context.Context, token string) (string, error) {
	key := c.bindKey(token)
	val, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return "", err
	}
	_ = c.client.Del(ctx, key)
	return val, nil
}

func (c *userCache) bindKey(token string) string {
	return fmt.Sprintf("eiam:user:bind:%s", token)
}
