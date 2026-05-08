package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

var (
	ErrCacheNotFound = redis.Nil
)

// IUserCache 用户业务相关的缓存接口
// 包含登录保护逻辑（失败重试、账号锁定）以及多因素认证/第三方绑定的临时状态管理
type IUserCache interface {
	// IncFailedAttempts 增加登录失败次数，用于防暴力破解
	IncFailedAttempts(ctx context.Context, username string, duration time.Duration) (int64, error)
	// ClearFailedAttempts 登录成功后重置失败计数
	ClearFailedAttempts(ctx context.Context, username string) error
	// SetLockout 手动设置账号锁定状态
	SetLockout(ctx context.Context, username string, duration time.Duration) error
	// IsLocked 检查账号是否处于锁定保护期
	IsLocked(ctx context.Context, username string) (bool, error)

	// SetBindState 存储三方账号绑定的临时状态，通常用于 OIDC 扫码后的二次确认流程
	SetBindState(ctx context.Context, token string, ident domain.OidcIdentity) error
	// GetBindState 获取并删除绑定状态，确保令牌的一次性安全性
	GetBindState(ctx context.Context, token string) (domain.OidcIdentity, error)

	// SetPasskeyState 存储 WebAuthn 握手过程中的挑战值与会话上下文
	SetPasskeyState(ctx context.Context, token string, data webauthn.SessionData) error
	// GetPasskeyState 获取并删除 Passkey 状态，防止重放攻击
	GetPasskeyState(ctx context.Context, token string) (webauthn.SessionData, error)
}

// userCache 实现了 IUserCache 接口
// 核心设计思路是采用组合模式，将通用的“临时状态存取”逻辑通过泛型组件 StateCache 进行封装
// 这样可以确保所有安全相关的临时令牌都具备一致的 TTL 管理和“读后即焚”特性
type userCache struct {
	client redis.Cmdable
	// bindCache 内部使用 OidcIdentity 泛型，明确其存储业务语义
	bindCache *StateCache[domain.OidcIdentity]
	// passkeyCache 强类型限制为 webauthn.SessionData，提供更好的开发体验和类型安全
	passkeyCache *StateCache[webauthn.SessionData]
}

func NewUserCache(client redis.Cmdable) IUserCache {
	return &userCache{
		client: client,
		// NOTE: 统一设置 5 分钟过期时间，作为安全敏感操作的通用窗口期
		bindCache:    NewStateCache[domain.OidcIdentity](client, "user:bind", 5*time.Minute),
		passkeyCache: NewStateCache[webauthn.SessionData](client, "user:passkey", 5*time.Minute),
	}
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

func (c *userCache) SetBindState(ctx context.Context, token string, ident domain.OidcIdentity) error {
	return c.bindCache.Set(ctx, token, ident)
}

func (c *userCache) GetBindState(ctx context.Context, token string) (domain.OidcIdentity, error) {
	return c.bindCache.Get(ctx, token)
}

func (c *userCache) SetPasskeyState(ctx context.Context, token string, data webauthn.SessionData) error {
	return c.passkeyCache.Set(ctx, token, data)
}

func (c *userCache) GetPasskeyState(ctx context.Context, token string) (webauthn.SessionData, error) {
	return c.passkeyCache.Get(ctx, token)
}

func (c *userCache) failedAttemptsKey(username string) string {
	return fmt.Sprintf("eiam:user:failed_attempts:%s", username)
}

func (c *userCache) lockoutKey(username string) string {
	return fmt.Sprintf("eiam:user:lockout:%s", username)
}
