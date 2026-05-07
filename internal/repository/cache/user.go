package cache

import (
	"context"
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
