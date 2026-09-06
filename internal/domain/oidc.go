package domain

import (
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthCode 授权码领域实体 (承载一次授权交互状态)
type AuthCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              int64     `json:"user_id"`
	Username            string    `json:"username"`
	TenantID            int64     `json:"tenant_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scopes              []string  `json:"scopes"`
	Nonce               string    `json:"nonce"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	CreatedAt           time.Time `json:"created_at"`
}

// BuildRedirectURL 拼接带有授权码与状态的完整回调地址
func (a *AuthCode) BuildRedirectURL(state string) (string, error) {
	parsed, err := url.Parse(a.RedirectURI)
	if err != nil {
		return "", err
	}
	q := parsed.Query()
	q.Set("code", a.Code)
	if state != "" {
		q.Set("state", state)
	}
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

// IsExpired 判断授权码是否已超时
func (a *AuthCode) IsExpired(ttl time.Duration) bool {
	return time.Since(a.CreatedAt) > ttl
}

// IDTokenClaims OIDC ID Token 结构定义
type IDTokenClaims struct {
	jwt.RegisteredClaims
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Nickname          string   `json:"nickname,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	PhoneNumber       string   `json:"phone_number,omitempty"`
	TenantID          int64    `json:"tenant_id,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	Nonce             string   `json:"nonce,omitempty"`
}

// TokenRequest 授权码换发 Token 请求参数
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	RefreshToken string `json:"refresh_token"`
}

// OidcTokenResult 换发令牌结果领域对象
type OidcTokenResult struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OidcUserInfo 用户信息查询领域对象
type OidcUserInfo struct {
	Subject           string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Name              string   `json:"name,omitempty"`
	Nickname          string   `json:"nickname,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	PhoneNumber       string   `json:"phone_number,omitempty"`
	TenantID          int64    `json:"tenant_id,omitempty"`
	Roles             []string `json:"roles,omitempty"`
}

// ConsentInfo 用户授权确认页上下文数据
type ConsentInfo struct {
	ConsentID           string   `json:"consent_id"`
	ClientID            string   `json:"client_id"`
	ClientName          string   `json:"client_name"`
	ClientLogo          string   `json:"client_logo"`
	UserID              int64    `json:"user_id"`
	Username            string   `json:"username"`
	TenantID            int64    `json:"tenant_id"`
	RedirectURI         string   `json:"redirect_uri"`
	Scopes              []string `json:"scopes"`
	ScopeDescriptions   []string `json:"scope_descriptions"`
	State               string   `json:"state"`
	Nonce               string   `json:"nonce"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	CreatedAt           int64    `json:"created_at"`
}

// RefreshTokenSession 刷新令牌存储会话实体
type RefreshTokenSession struct {
	RefreshToken string   `json:"refresh_token"`
	ClientID     string   `json:"client_id"`
	UserID       int64    `json:"user_id"`
	Username     string   `json:"username"`
	TenantID     int64    `json:"tenant_id"`
	Scopes       []string `json:"scopes"`
	CreatedAt    int64    `json:"created_at"`
}

// OidcDiscovery 自动发现元数据领域对象 (扩展 RFC 7009 与 RP-Initiated Logout)
type OidcDiscovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
}

// NewOidcDiscovery 构建标准 Discovery 元数据实体
func NewOidcDiscovery(issuerURL string) OidcDiscovery {
	trimmed := strings.TrimRight(issuerURL, "/")
	return OidcDiscovery{
		Issuer:                            trimmed,
		AuthorizationEndpoint:             trimmed + "/oauth/v2/authorize",
		TokenEndpoint:                     trimmed + "/oauth/v2/token",
		UserinfoEndpoint:                  trimmed + "/userinfo",
		JwksURI:                           trimmed + "/oauth/v2/jwks",
		RevocationEndpoint:                trimmed + "/oauth/v2/revoke",
		EndSessionEndpoint:                trimmed + "/oauth/v2/logout",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "profile", "email", "phone"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "preferred_username", "nickname", "email", "roles", "tenant_id",
		},
		CodeChallengeMethodsSupported: []string{"S256", "plain"},
		GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
	}
}

// ResolveScopeDescriptions 将请求的 Scope 列表转换为易于理解的用户授权描述
func ResolveScopeDescriptions(scopes []string) []string {
	descriptions := make([]string, 0, len(scopes))
	for _, s := range scopes {
		switch s {
		case "openid":
			descriptions = append(descriptions, "获取您的 OpenID 唯一身份标识")
		case "profile":
			descriptions = append(descriptions, "读取您的个人资料 (姓名、昵称)")
		case "email":
			descriptions = append(descriptions, "读取您的电子邮箱地址")
		case "phone":
			descriptions = append(descriptions, "读取您的手机联系方式")
		case "roles":
			descriptions = append(descriptions, "读取您在租户下的角色权限")
		default:
			descriptions = append(descriptions, "访问权限: "+s)
		}
	}
	return descriptions
}

