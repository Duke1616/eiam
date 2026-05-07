package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type IIdentitySourceCache interface {
	SetState(ctx context.Context, state string, sourceID int64, nonce string) error
	GetState(ctx context.Context, state string) (sourceID int64, nonce string, err error)
}

type redisIdentitySourceCache struct {
	cmd redis.Cmdable
}

func NewIdentitySourceCache(cmd redis.Cmdable) IIdentitySourceCache {
	return &redisIdentitySourceCache{cmd: cmd}
}

func (c *redisIdentitySourceCache) SetState(ctx context.Context, state string, sourceID int64, nonce string) error {
	key := c.stateKey(state)
	// 使用 Redis Hash 存储 sourceID 和 nonce
	if err := c.cmd.HSet(ctx, key, "source_id", sourceID, "nonce", nonce).Err(); err != nil {
		return err
	}
	return c.cmd.Expire(ctx, key, 5*time.Minute).Err()
}

func (c *redisIdentitySourceCache) GetState(ctx context.Context, state string) (int64, string, error) {
	key := c.stateKey(state)
	result, err := c.cmd.HGetAll(ctx, key).Result()
	if err != nil {
		return 0, "", err
	}

	if len(result) == 0 {
		return 0, "", fmt.Errorf("state not found or expired")
	}

	sourceID, err := parseRedisInt64(result["source_id"])
	if err != nil {
		return 0, "", err
	}

	nonce := result["nonce"]

	// 读取后立即删除，确保一次性
	_ = c.cmd.Del(ctx, key)
	return sourceID, nonce, nil
}

func parseRedisInt64(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty value")
	}
	var v int64
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}

func (c *redisIdentitySourceCache) stateKey(state string) string {
	return fmt.Sprintf("oidc:state:%s", state)
}
