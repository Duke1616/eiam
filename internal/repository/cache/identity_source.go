package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/redis/go-redis/v9"
)

// IIdentitySourceCache 身份源相关的缓存接口
// 主要用于存储 OIDC 登录流程中的中间状态（State/Nonce），防止 CSRF 和重放攻击
type IIdentitySourceCache interface {
	// SetState 存储 OIDC 状态（兼容接口）
	SetState(ctx context.Context, state string, sourceID int64, nonce string) error
	// GetState 获取并销毁 OIDC 状态（兼容接口）
	GetState(ctx context.Context, state string) (sourceID int64, nonce string, err error)
	// SetStateContext 存储完整的 OAuth 业务上下文
	SetStateContext(ctx context.Context, stateCtx domain.OAuthStateContext) error
	// GetDelStateContext 原子获取并销毁 OAuth 业务上下文（阅后即焚防重放）
	GetDelStateContext(ctx context.Context, state string) (domain.OAuthStateContext, error)
}

type redisIdentitySourceCache struct {
	cmd redis.Cmdable
}

func NewIdentitySourceCache(cmd redis.Cmdable) IIdentitySourceCache {
	return &redisIdentitySourceCache{cmd: cmd}
}

func (c *redisIdentitySourceCache) SetState(ctx context.Context, state string, sourceID int64, nonce string) error {
	return c.SetStateContext(ctx, domain.OAuthStateContext{
		StateID:   state,
		SourceID:  sourceID,
		Nonce:     nonce,
		CreatedAt: time.Now().Unix(),
	})
}

func (c *redisIdentitySourceCache) GetState(ctx context.Context, state string) (int64, string, error) {
	sCtx, err := c.GetDelStateContext(ctx, state)
	if err != nil {
		return 0, "", err
	}
	return sCtx.SourceID, sCtx.Nonce, nil
}

func (c *redisIdentitySourceCache) SetStateContext(ctx context.Context, stateCtx domain.OAuthStateContext) error {
	key := c.stateKey(stateCtx.StateID)
	data, err := json.Marshal(stateCtx)
	if err != nil {
		return fmt.Errorf("序列化 OAuthStateContext 失败: %w", err)
	}

	// 统一保留 10 分钟授权交互有效期
	return c.cmd.Set(ctx, key, data, 10*time.Minute).Err()
}

func (c *redisIdentitySourceCache) GetDelStateContext(ctx context.Context, state string) (domain.OAuthStateContext, error) {
	key := c.stateKey(state)

	// 优先尝试 Redis 6.2+ 原生 GETDEL 命令（单操作原子读取并销毁）
	val, err := c.cmd.GetDel(ctx, key).Result()
	if err == nil {
		var sCtx domain.OAuthStateContext
		if unmarshalErr := json.Unmarshal([]byte(val), &sCtx); unmarshalErr != nil {
			return domain.OAuthStateContext{}, fmt.Errorf("反序列化 OAuthStateContext 失败: %w", unmarshalErr)
		}
		return sCtx, nil
	}

	// 若未找到键值
	if errors.Is(err, redis.Nil) {
		return domain.OAuthStateContext{}, fmt.Errorf("state 不存在或已过期")
	}

	// 降级兜底兼容：处理存量的 Redis Hash 格式
	result, hashErr := c.cmd.HGetAll(ctx, key).Result()
	if hashErr == nil && len(result) > 0 {
		_ = c.cmd.Del(ctx, key)
		sourceID, _ := parseRedisInt64(result["source_id"])
		return domain.OAuthStateContext{
			StateID:  state,
			SourceID: sourceID,
			Nonce:    result["nonce"],
		}, nil
	}

	return domain.OAuthStateContext{}, fmt.Errorf("获取 state 上下文失败: %w", err)
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
