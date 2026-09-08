package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidApplicationName 应用名称非法
	ErrInvalidApplicationName = errors.New("应用名称不能为空且长度不能超过64字符")
	// ErrUnsupportedProtocol 不支持的应用单点登录协议类型
	ErrUnsupportedProtocol = errors.New("不支持的应用单点登录协议类型")
	// ErrInvalidRedirectURI 回调地址不合法
	ErrInvalidRedirectURI = errors.New("回调地址必须为绝对路径且禁止携带Fragment(#)")
)

// Protocol 应用单点登录协议类型枚举
type Protocol string

const (
	ProtocolOIDC Protocol = "oidc"
	ProtocolCAS  Protocol = "cas"
	ProtocolSAML Protocol = "saml"
)

// String 实现 fmt.Stringer 接口
func (p Protocol) String() string {
	return string(p)
}

// DisplayName 返回协议的人类可读友好显示名称
func (p Protocol) DisplayName() string {
	switch p {
	case ProtocolOIDC:
		return "OIDC / OAuth 2.0"
	case ProtocolCAS:
		return "CAS 2.0 / 3.0"
	case ProtocolSAML:
		return "SAML 2.0"
	default:
		return string(p)
	}
}

// IsValid 校验当前协议是否为系统受支持的合法枚举
func (p Protocol) IsValid() bool {
	switch p {
	case ProtocolOIDC, ProtocolCAS, ProtocolSAML:
		return true
	default:
		return false
	}
}

// IsOIDC 判断是否为 OIDC / OAuth 2.0 协议
func (p Protocol) IsOIDC() bool {
	return p == ProtocolOIDC
}

// IsCAS 判断是否为 CAS 协议
func (p Protocol) IsCAS() bool {
	return p == ProtocolCAS
}

// IsSAML 判断是否为 SAML 协议
func (p Protocol) IsSAML() bool {
	return p == ProtocolSAML
}

// ParseProtocol 将字符串安全转换为 Protocol 枚举
func ParseProtocol(s string) (Protocol, bool) {
	p := Protocol(strings.ToLower(strings.TrimSpace(s)))
	if p.IsValid() {
		return p, true
	}
	return "", false
}

// Application 接入 EIAM 的统一业务系统应用领域实体 (兼容 OIDC, CAS, SAML 等多协议)
type Application struct {
	ID               int64     `json:"id"`
	TenantID         int64     `json:"tenant_id"`          // 归属租户 ID (0 表示全局应用)
	Protocol         Protocol  `json:"protocol"`           // 单点登录协议类型: oidc / cas / saml
	ClientID         string    `json:"client_id"`          // 应用唯一标识符 / 客户端ID
	ClientSecret     string    `json:"client_secret"`      // 明文客户端密钥 (仅创建/重置时返回)
	ClientSecretHash string    `json:"client_secret_hash"` // 密码学哈希 (存储持久化)
	Name             string    `json:"name"`               // 应用显示名称 (如 "JumpServer堡垒机", "Grafana监控")
	Logo             string    `json:"logo"`               // 应用图标 URL (应用门户展示)
	HomepageURL      string    `json:"homepage_url"`       // 应用系统主页 URL (一键直达)
	RedirectURIs     []string  `json:"redirect_uris"`      // 严格合法的回调地址 / Service 白名单
	ResponseTypes    []string  `json:"response_types"`     // 允许的响应类型 (e.g. ["code"])
	GrantTypes       []string  `json:"grant_types"`        // 允许的授权模式 (e.g. ["authorization_code", "refresh_token"])
	Scopes           []string  `json:"scopes"`             // 允许申请的权限范围 (e.g. ["openid", "profile", "email"])
	IsPublic         bool      `json:"is_public"`          // 是否为公共客户端 (SPA/移动应用无客户端密钥)
	AutoConsent      bool      `json:"auto_consent"`       // 是否跳过用户显式授权确认 (第一方应用默认为 true)
	Ctime            time.Time `json:"ctime"`
	Utime            time.Time `json:"utime"`
}

// SupportsProtocol 检查应用是否支持指定的单点登录协议
// 对未显式指定协议的历史旧数据平滑回退支持 OIDC
func (a *Application) SupportsProtocol(p Protocol) bool {
	if a.Protocol == p {
		return true
	}
	if a.Protocol == "" && p.IsOIDC() {
		return true
	}
	return false
}

// IsConfidential 判定是否为机密客户端 (与 IsPublic 互斥，具备后端保密凭据存储能力)
func (a *Application) IsConfidential() bool {
	return !a.IsPublic
}

// Validate 统一执行应用实体的业务不变量与安全性领域自校验
func (a *Application) Validate() error {
	trimmedName := strings.TrimSpace(a.Name)
	if trimmedName == "" || utf8.RuneCountInString(trimmedName) > 64 {
		return ErrInvalidApplicationName
	}

	if a.Protocol != "" && !a.Protocol.IsValid() {
		return ErrUnsupportedProtocol
	}

	if !a.ValidateRedirectURIs() {
		return ErrInvalidRedirectURI
	}

	return nil
}

// HasRedirectURI 遵循具体协议规范自适应校验回调地址是否合法 (OIDC 精确比对 / CAS 路径前缀与同源比对)
func (a *Application) HasRedirectURI(rawURI string) bool {
	if a.Protocol.IsCAS() {
		return a.MatchesCasService(rawURI)
	}
	return a.matchesOIDCRedirectURI(rawURI)
}

// matchesOIDCRedirectURI 遵循 RFC 6749 Section 3.1.2 严格校验 OAuth 2.0 / OIDC 回调地址白名单 (防开放重定向)
func (a *Application) matchesOIDCRedirectURI(rawURI string) bool {
	parsed, err := url.Parse(rawURI)
	if err != nil || !parsed.IsAbs() || parsed.Fragment != "" {
		// RFC 6749 禁止回调 URL 携带 Fragment (#)
		return false
	}

	// 1. 完全字符串精确匹配
	if slices.Contains(a.RedirectURIs, rawURI) {
		return true
	}

	// 2. 本地开发调试友好性：支持 localhost / 127.0.0.1 动态端口匹配
	if parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" {
		for _, allowed := range a.RedirectURIs {
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

// MatchesCasService 遵循 CAS 协议规范比对目标 Service 是否在应用白名单中 (同源 + 路径前缀匹配)
func (a *Application) MatchesCasService(rawService string) bool {
	reqURL, err := url.Parse(rawService)
	if err != nil || !reqURL.IsAbs() {
		return false
	}

	for _, allowed := range a.RedirectURIs {
		if allowed == rawService {
			return true
		}
		targetURL, err := url.Parse(allowed)
		if err != nil {
			continue
		}

		// 1. 同源校验：Scheme 和 Host (含端口) 必须严格一致 (大小写不敏感，防域名伪造)
		if !strings.EqualFold(targetURL.Scheme, reqURL.Scheme) || !strings.EqualFold(targetURL.Host, reqURL.Host) {
			continue
		}

		// 2. 路径匹配：白名单为全站根路径，或为请求路径的前缀
		if targetURL.Path == "" || targetURL.Path == "/" || strings.HasPrefix(reqURL.Path, targetURL.Path) {
			return true
		}
	}

	return false
}

// HasScope 校验请求的 Scope 是否在允许范围内
func (a *Application) HasScope(scope string) bool {
	return slices.Contains(a.Scopes, scope)
}

// ValidateRedirectURIs 校验应用配置时的全部白名单格式是否合法
func (a *Application) ValidateRedirectURIs() bool {
	if len(a.RedirectURIs) == 0 {
		return false
	}
	for _, raw := range a.RedirectURIs {
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

// InitDefaultConfig 初始化并补齐应用默认配置参数 (具备协议感知能力)
func (a *Application) InitDefaultConfig() {
	if a.Protocol == "" {
		a.Protocol = ProtocolOIDC
	}

	if a.Protocol.IsOIDC() {
		if len(a.ResponseTypes) == 0 {
			a.ResponseTypes = []string{"code"}
		}
		if len(a.GrantTypes) == 0 {
			a.GrantTypes = []string{"authorization_code", "refresh_token"}
		}
		if len(a.Scopes) == 0 {
			a.Scopes = []string{"openid", "profile", "email"}
		}
	} else if a.Protocol.IsCAS() {
		// CAS 协议不需要 OIDC 专有的 response_types/grant_types/scopes，清理以保持数据纯粹
		a.ResponseTypes = nil
		a.GrantTypes = nil
		a.Scopes = nil
	}
}

// SetSecret 设置明文密钥并同步计算保存密码学哈希
func (a *Application) SetSecret(rawSecret string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	a.ClientSecret = rawSecret
	a.ClientSecretHash = string(hash)
	return nil
}

// VerifySecret 校验传入的明文密钥与实体存储的哈希是否一致
func (a *Application) VerifySecret(rawSecret string) bool {
	if a.IsPublic {
		return true
	}
	if a.ClientSecretHash == "" || rawSecret == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(a.ClientSecretHash), []byte(rawSecret)) == nil
}

// VerifyPKCE 校验 PKCE S256/Plain 挑战码
func (a *Application) VerifyPKCE(verifier, challenge, method string) bool {
	if method == "plain" {
		return verifier == challenge
	}
	// 默认 S256: BASE64URL(SHA256(verifier))
	h := sha256.Sum256([]byte(verifier))
	calculated := base64.RawURLEncoding.EncodeToString(h[:])
	return calculated == challenge
}

// IsGrantTypeAllowed 校验客户端是否允许使用指定的 GrantType 授权模式
func (a *Application) IsGrantTypeAllowed(grantType string) bool {
	if len(a.GrantTypes) == 0 {
		return grantType == "authorization_code"
	}
	return slices.Contains(a.GrantTypes, grantType)
}

// FilterAllowedScopes 过滤请求中属于该客户端配置范围内的有效 Scopes
func (a *Application) FilterAllowedScopes(reqScopes []string) []string {
	if len(reqScopes) == 0 {
		return a.Scopes
	}
	res := make([]string, 0, len(reqScopes))
	for _, s := range reqScopes {
		if a.HasScope(s) {
			res = append(res, s)
		}
	}
	if len(res) == 0 {
		return []string{"openid"}
	}
	return res
}
