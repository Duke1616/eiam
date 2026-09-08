package grant

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/service/idp/claims"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// IKeySigner 提取 JWT 签名所需的最小接口契约
type IKeySigner interface {
	SignJWT(claims jwt.Claims) (string, error)
}

// IGrantHandler OAuth2.0 / OIDC 授权模式策略接口 (Strategy Pattern)
type IGrantHandler interface {
	// GrantType 返回当前策略支持的 grant_type 名称
	GrantType() string
	// Handle 执行具体的令牌换发与校验流程
	Handle(ctx context.Context, req domain.TokenRequest, app domain.Application, issuerURL string) (*domain.OidcTokenResult, error)
}

// TokenOptions Token 签发配置项（借鉴 ginx Options 模式，让过期时间可配置而非硬编码）
type TokenOptions struct {
	AccessTokenTTL time.Duration // Access Token 有效期，默认 2h
	IDTokenTTL     time.Duration // ID Token 有效期，默认 1h
	// nowFunc 控制当前时间，方便测试固定签发时间（借鉴 ginx 的 nowFunc 思路）
	nowFunc func() time.Time
}

// WithAccessTokenTTL 自定义 Access Token 有效期
func WithAccessTokenTTL(d time.Duration) func(*TokenOptions) {
	return func(o *TokenOptions) {
		o.AccessTokenTTL = d
	}
}

// WithIDTokenTTL 自定义 ID Token 有效期
func WithIDTokenTTL(d time.Duration) func(*TokenOptions) {
	return func(o *TokenOptions) {
		o.IDTokenTTL = d
	}
}

// WithNowFunc 替换时间函数（用于测试时固定签发时间，与 ginx 的 WithNowFunc 思路一致）
func WithNowFunc(fn func() time.Time) func(*TokenOptions) {
	return func(o *TokenOptions) {
		o.nowFunc = fn
	}
}

func defaultTokenOptions() TokenOptions {
	return TokenOptions{
		AccessTokenTTL: 2 * time.Hour,
		IDTokenTTL:     1 * time.Hour,
		nowFunc:        time.Now,
	}
}

// TokenPayload IssueTokenPair 的统一入参
type TokenPayload struct {
	IssuerURL string
	ClientID  string
	Claims    claims.Claims
	Nonce     string
}

// IssueTokenPair 统一的 AccessToken 与 IDToken 签发生成器 (消除策略间的重复代码)
// 参考 ginx Management.GenerateAccessToken 的写法：配置与数据分离，时间可注入
func IssueTokenPair(signer IKeySigner, payload TokenPayload, opts ...func(*TokenOptions)) (accessToken, idToken string, err error) {
	o := defaultTokenOptions()
	for _, opt := range opts {
		opt(&o)
	}

	trimmedIssuer := strings.TrimRight(payload.IssuerURL, "/")
	now := o.nowFunc()

	// 1. 签发 ID Token（含 Nonce，TTL 较短）
	idToken, err = signer.SignJWT(buildClaims(payload, trimmedIssuer, now, o.IDTokenTTL, payload.Nonce))
	if err != nil {
		return "", "", fmt.Errorf("签发 ID Token 失败: %w", err)
	}

	// 2. 签发 Access Token（不含 Nonce，TTL 较长）
	accessToken, err = signer.SignJWT(buildClaims(payload, trimmedIssuer, now, o.AccessTokenTTL, ""))
	if err != nil {
		return "", "", fmt.Errorf("签发 Access Token 失败: %w", err)
	}

	return accessToken, idToken, nil
}

// buildClaims 构造标准 OIDC Claims（IDToken 与 AccessToken 共享同一结构，仅 TTL 与 Nonce 有别）
func buildClaims(payload TokenPayload, issuer string, now time.Time, ttl time.Duration, nonce string) domain.IDTokenClaims {
	return domain.IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   payload.Claims.Subject,
			Audience:  jwt.ClaimStrings{payload.ClientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		PreferredUsername: payload.Claims.Username,
		Nickname:          payload.Claims.Nickname,
		Email:             payload.Claims.Email,
		EmailVerified:     payload.Claims.Email != "",
		PhoneNumber:       payload.Claims.Phone,
		TenantID:          payload.Claims.TenantID,
		Roles:             payload.Claims.Roles,
		Nonce:             nonce,
	}
}

// GenerateRandomString 生成指定长度的高强度加密随机字符串 (URL 安全)
func GenerateRandomString(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
