package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	authRequestPrefix       = "eiam:idp:auth_req:"
	authCodePrefix          = "eiam:idp:code:"
	consentPrefix           = "eiam:idp:consent:"
	refreshTokenPrefix      = "eiam:idp:refresh_token:"
	userRefreshTokensPrefix = "eiam:idp:user_tokens:"
	revokedTokenPrefix      = "eiam:idp:revoked:"
	clusterSigningKeyPrefix = "eiam:idp:cluster_signing_key:"
	oauthClientPrefix       = "eiam:idp:oauth_client:"
	authReqTTL              = 10 * time.Minute
	authCodeTTL             = 5 * time.Minute
	consentTTL              = 10 * time.Minute
	refreshTokenTTL         = 30 * 24 * time.Hour
	oauthClientTTL          = 1 * time.Hour
)

// IOidcCache OIDC 认证状态与元数据缓存接口
type IOidcCache interface {
	// SaveAuthCodeContext 缓存授权码会话数据 (包含用户ID、客户端ID、Scope等)
	SaveAuthCodeContext(ctx context.Context, code string, data []byte) error
	// GetAndDelAuthCodeContext 原子获取并删除授权码数据，防止重放
	GetAndDelAuthCodeContext(ctx context.Context, code string) ([]byte, error)
	// SaveConsentContext 缓存待授权确认会话数据 (Consent)
	SaveConsentContext(ctx context.Context, consentID string, data []byte) error
	// GetConsentContext 获取待确认授权数据 (只读不删)
	GetConsentContext(ctx context.Context, consentID string) ([]byte, error)
	// GetAndDelConsentContext 获取并删除待确认授权数据
	GetAndDelConsentContext(ctx context.Context, consentID string) ([]byte, error)
	// SaveRefreshToken 保存 RefreshToken 会话数据
	SaveRefreshToken(ctx context.Context, token string, data []byte) error
	// GetRefreshToken 获取 RefreshToken 会话数据
	GetRefreshToken(ctx context.Context, token string) ([]byte, error)
	// DeleteRefreshToken 删除指定的 RefreshToken
	DeleteRefreshToken(ctx context.Context, token string) error
	// RevokeToken 将已吊销的 Token 写入黑名单
	RevokeToken(ctx context.Context, token string, ttl time.Duration) error
	// IsTokenRevoked 检查 Token 是否已被吊销
	IsTokenRevoked(ctx context.Context, token string) (bool, error)
	// TrackUserRefreshToken 记录用户与 RefreshToken 的关联关系
	TrackUserRefreshToken(ctx context.Context, userID, token string) error
	// DeleteUserRefreshTokens 批量清理用户下所有的 RefreshToken
	DeleteUserRefreshTokens(ctx context.Context, userID string) error
	// GetOrSetClusterSigningKey 获取或初始化集群共享的 RSA 签名私钥 PEM
	GetOrSetClusterSigningKey(ctx context.Context, keyID string, generateFn func() (string, error)) (string, error)
	// SaveOAuthClient 缓存客户端元数据
	SaveOAuthClient(ctx context.Context, clientID string, data []byte) error
	// GetOAuthClient 获取客户端元数据缓存
	GetOAuthClient(ctx context.Context, clientID string) ([]byte, error)
	// DeleteOAuthClient 删除客户端元数据缓存
	DeleteOAuthClient(ctx context.Context, clientID string) error
	// Ping 缓存服务连通性检查
	Ping(ctx context.Context) error
}

type oidcCache struct {
	cmd redis.Cmdable
}

// NewOidcCache 实例化 OIDC 缓存仓储组件
func NewOidcCache(cmd redis.Cmdable) IOidcCache {
	return &oidcCache{cmd: cmd}
}

func (c *oidcCache) SaveAuthCodeContext(ctx context.Context, code string, data []byte) error {
	return c.cmd.Set(ctx, authCodePrefix+code, data, authCodeTTL).Err()
}

func (c *oidcCache) GetAndDelAuthCodeContext(ctx context.Context, code string) ([]byte, error) {
	// 使用 Redis 原生 GETDEL 实现原子读取并销毁，彻底根除高并发下的 Code 双花重放
	bytes, err := c.cmd.GetDel(ctx, authCodePrefix+code).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("invalid or expired code")
	}
	return bytes, err
}

func (c *oidcCache) SaveConsentContext(ctx context.Context, consentID string, data []byte) error {
	return c.cmd.Set(ctx, consentPrefix+consentID, data, consentTTL).Err()
}

func (c *oidcCache) GetConsentContext(ctx context.Context, consentID string) ([]byte, error) {
	bytes, err := c.cmd.Get(ctx, consentPrefix+consentID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("invalid or expired consent session")
	}
	return bytes, err
}

func (c *oidcCache) GetAndDelConsentContext(ctx context.Context, consentID string) ([]byte, error) {
	bytes, err := c.cmd.GetDel(ctx, consentPrefix+consentID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("invalid or expired consent session")
	}
	return bytes, err
}

func (c *oidcCache) SaveRefreshToken(ctx context.Context, token string, data []byte) error {
	return c.cmd.Set(ctx, refreshTokenPrefix+token, data, refreshTokenTTL).Err()
}

func (c *oidcCache) GetRefreshToken(ctx context.Context, token string) ([]byte, error) {
	bytes, err := c.cmd.Get(ctx, refreshTokenPrefix+token).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("refresh token not found")
	}
	return bytes, err
}

func (c *oidcCache) DeleteRefreshToken(ctx context.Context, token string) error {
	return c.cmd.Del(ctx, refreshTokenPrefix+token).Err()
}

func (c *oidcCache) RevokeToken(ctx context.Context, token string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return c.cmd.Set(ctx, revokedTokenPrefix+token, "1", ttl).Err()
}

func (c *oidcCache) IsTokenRevoked(ctx context.Context, token string) (bool, error) {
	val, err := c.cmd.Get(ctx, revokedTokenPrefix+token).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return val == "1", nil
}

func (c *oidcCache) TrackUserRefreshToken(ctx context.Context, userID, token string) error {
	if userID == "" || token == "" {
		return nil
	}
	key := userRefreshTokensPrefix + userID
	pipe := c.cmd.Pipeline()
	pipe.SAdd(ctx, key, token)
	pipe.Expire(ctx, key, refreshTokenTTL)
	_, err := pipe.Exec(ctx)
	return err
}

func (c *oidcCache) DeleteUserRefreshTokens(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	key := userRefreshTokensPrefix + userID
	tokens, err := c.cmd.SMembers(ctx, key).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}

	pipe := c.cmd.Pipeline()
	for _, tok := range tokens {
		pipe.Del(ctx, refreshTokenPrefix+tok)
	}
	pipe.Del(ctx, key)
	_, err = pipe.Exec(ctx)
	return err
}

func (c *oidcCache) GetOrSetClusterSigningKey(ctx context.Context, keyID string, generateFn func() (string, error)) (string, error) {
	key := clusterSigningKeyPrefix + keyID
	val, err := c.cmd.Get(ctx, key).Result()
	if err == nil && val != "" {
		return val, nil
	}
	if err != nil && !errors.Is(err, redis.Nil) {
		return "", err
	}

	// 利用分布式锁/SETNX 保证多副本并发初始化时只有单个 Pod 生成并持久化
	pemContent, genErr := generateFn()
	if genErr != nil {
		return "", genErr
	}

	ok, setErr := c.cmd.SetNX(ctx, key, pemContent, 0).Result()
	if setErr != nil {
		return "", setErr
	}
	if !ok {
		// 并发竞争由其他 Pod 写入成功，重新读取获取权威 PEM
		return c.cmd.Get(ctx, key).Result()
	}
	return pemContent, nil
}

func (c *oidcCache) SaveOAuthClient(ctx context.Context, clientID string, data []byte) error {
	return c.cmd.Set(ctx, oauthClientPrefix+clientID, data, oauthClientTTL).Err()
}

func (c *oidcCache) GetOAuthClient(ctx context.Context, clientID string) ([]byte, error) {
	bytes, err := c.cmd.Get(ctx, oauthClientPrefix+clientID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("oauth client cache not found")
	}
	return bytes, err
}

func (c *oidcCache) DeleteOAuthClient(ctx context.Context, clientID string) error {
	return c.cmd.Del(ctx, oauthClientPrefix+clientID).Err()
}

func (c *oidcCache) Ping(ctx context.Context) error {
	return c.cmd.Ping(ctx).Err()
}
