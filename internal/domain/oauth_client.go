package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// OAuthClient 接入 EIAM 的下游应用领域实体 (OIDC/OAuth2 Relying Party)
type OAuthClient struct {
	ID               int64     `json:"id"`
	TenantID         int64     `json:"tenant_id"`          // 归属租户 ID (0 表示全局应用)
	ClientID         string    `json:"client_id"`          // 客户端唯一标识
	ClientSecret     string    `json:"client_secret"`      // 明文客户端密钥 (仅创建/重置时返回)
	ClientSecretHash string    `json:"client_secret_hash"` // 密码学哈希 (存储持久化)
	Name             string    `json:"name"`               // 应用显示名称 (如 "Grafana", "CRM")
	Logo             string    `json:"logo"`               // 应用图标 URL
	RedirectURIs     []string  `json:"redirect_uris"`      // 严格合法的回调地址白名单
	ResponseTypes    []string  `json:"response_types"`     // 允许的响应类型 (e.g. ["code"])
	GrantTypes       []string  `json:"grant_types"`        // 允许的授权模式 (e.g. ["authorization_code", "refresh_token"])
	Scopes           []string  `json:"scopes"`             // 允许申请的权限范围 (e.g. ["openid", "profile", "email"])
	IsPublic         bool      `json:"is_public"`          // 是否为公共客户端 (SPA/移动应用无客户端密钥)
	AutoConsent      bool      `json:"auto_consent"`       // 是否跳过用户显式授权确认 (第一方应用默认为 true)
	Ctime            time.Time `json:"ctime"`
	Utime            time.Time `json:"utime"`
}

// HasRedirectURI 遵循 RFC 6749 Section 3.1.2 严格校验回调地址白名单 (防开放重定向)
func (c *OAuthClient) HasRedirectURI(rawURI string) bool {
	normURI := rawURI
	// 若传入的 URI 被二次 URL 编码，解码归一化
	if unescaped, err := url.QueryUnescape(rawURI); err == nil && strings.HasPrefix(unescaped, "http") {
		normURI = unescaped
	}

	parsed, err := url.Parse(normURI)
	if err != nil || !parsed.IsAbs() || parsed.Fragment != "" {
		// RFC 6749 禁止回调 URL 携带 Fragment (#)
		return false
	}

	// 1. 精确匹配
	if slices.Contains(c.RedirectURIs, normURI) {
		return true
	}

	// 2. 忽略尾部斜杠容错匹配
	trimmedNorm := strings.TrimRight(normURI, "/")
	for _, allowed := range c.RedirectURIs {
		if strings.TrimRight(allowed, "/") == trimmedNorm {
			return true
		}
	}

	// 3. 本地开发调试友好性：支持 localhost / 127.0.0.1 动态端口匹配
	if parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" {
		for _, allowed := range c.RedirectURIs {
			allowedParsed, err := url.Parse(allowed)
			if err == nil && (allowedParsed.Hostname() == "localhost" || allowedParsed.Hostname() == "127.0.0.1") {
				if allowedParsed.Path == parsed.Path && allowedParsed.Scheme == parsed.Scheme {
					return true
				}
			}
		}
	}

	return false
}

// HasScope 校验请求的 Scope 是否在允许范围内
func (c *OAuthClient) HasScope(scope string) bool {
	return slices.Contains(c.Scopes, scope)
}

// ValidateRedirectURIs 校验应用配置时的全部白名单格式是否合法
func (c *OAuthClient) ValidateRedirectURIs() bool {
	if len(c.RedirectURIs) == 0 {
		return false
	}
	for _, raw := range c.RedirectURIs {
		parsed, err := url.Parse(raw)
		if err != nil || !parsed.IsAbs() || parsed.Fragment != "" {
			return false
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "http" && scheme != "https" && !strings.Contains(scheme, ".") {
			return false
		}
	}
	return true
}

// InitDefaultConfig 初始化并补齐应用默认配置参数
func (c *OAuthClient) InitDefaultConfig() {
	if len(c.ResponseTypes) == 0 {
		c.ResponseTypes = []string{"code"}
	}
	if len(c.GrantTypes) == 0 {
		c.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	}
}

// SetSecret 设置明文密钥并同步计算保存密码学哈希
func (c *OAuthClient) SetSecret(rawSecret string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	c.ClientSecret = rawSecret
	c.ClientSecretHash = string(hash)
	return nil
}

// VerifySecret 校验传入的明文密钥与实体存储的哈希是否一致
func (c *OAuthClient) VerifySecret(rawSecret string) bool {
	if c.IsPublic {
		return true
	}
	if c.ClientSecretHash == "" || rawSecret == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(c.ClientSecretHash), []byte(rawSecret)) == nil
}

// VerifyPKCE 校验 PKCE S256/Plain 挑战码
func (c *OAuthClient) VerifyPKCE(verifier, challenge, method string) bool {
	if method == "plain" {
		return verifier == challenge
	}
	// 默认 S256: BASE64URL(SHA256(verifier))
	h := sha256.Sum256([]byte(verifier))
	calculated := base64.RawURLEncoding.EncodeToString(h[:])
	return calculated == challenge
}

// IsGrantTypeAllowed 校验客户端是否允许使用指定的 GrantType 授权模式
func (c *OAuthClient) IsGrantTypeAllowed(grantType string) bool {
	if len(c.GrantTypes) == 0 {
		return grantType == "authorization_code"
	}
	return slices.Contains(c.GrantTypes, grantType)
}

// FilterAllowedScopes 过滤请求中属于该客户端配置范围内的有效 Scopes
func (c *OAuthClient) FilterAllowedScopes(reqScopes []string) []string {
	if len(reqScopes) == 0 {
		return c.Scopes
	}
	res := make([]string, 0, len(reqScopes))
	for _, s := range reqScopes {
		if c.HasScope(s) {
			res = append(res, s)
		}
	}
	if len(res) == 0 {
		return []string{"openid"}
	}
	return res
}


