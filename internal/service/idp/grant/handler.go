package grant

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
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
	Handle(ctx context.Context, req domain.TokenRequest, client domain.OAuthClient, issuerURL string) (*domain.OidcTokenResult, error)
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

// UserProfile 用户名片信息（借鉴 ginx 的结构体收拢思路，消除多参数函数签名）
type UserProfile struct {
	Nickname string
	Email    string
	Phone    string
}

// TokenPayload IssueTokenPair 的统一入参（替代原来 12 个裸参数）
type TokenPayload struct {
	IssuerURL string
	ClientID  string
	UserID    int64
	Username  string
	TenantID  int64
	Profile   UserProfile
	Roles     []string
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

	// 1. 签发 ID Token
	idClaims := domain.IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    trimmedIssuer,
			Subject:   strconv.FormatInt(payload.UserID, 10),
			Audience:  jwt.ClaimStrings{payload.ClientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(o.IDTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		PreferredUsername: payload.Username,
		Nickname:          payload.Profile.Nickname,
		Email:             payload.Profile.Email,
		EmailVerified:     payload.Profile.Email != "",
		PhoneNumber:       payload.Profile.Phone,
		TenantID:          payload.TenantID,
		Roles:             payload.Roles,
		Nonce:             payload.Nonce,
	}

	idToken, err = signer.SignJWT(idClaims)
	if err != nil {
		return "", "", fmt.Errorf("签发 ID Token 失败: %w", err)
	}

	// 2. 签发 Access Token
	accessClaims := domain.IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    trimmedIssuer,
			Subject:   strconv.FormatInt(payload.UserID, 10),
			Audience:  jwt.ClaimStrings{payload.ClientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(o.AccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		PreferredUsername: payload.Username,
		Nickname:          payload.Profile.Nickname,
		Email:             payload.Profile.Email,
		EmailVerified:     payload.Profile.Email != "",
		PhoneNumber:       payload.Profile.Phone,
		TenantID:          payload.TenantID,
		Roles:             payload.Roles,
	}

	accessToken, err = signer.SignJWT(accessClaims)
	if err != nil {
		return "", "", fmt.Errorf("签发 Access Token 失败: %w", err)
	}

	return accessToken, idToken, nil
}

// GenerateRandomString 生成指定长度的高强度加密随机字符串 (URL 安全)
func GenerateRandomString(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
