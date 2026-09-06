package domain

import (
	"fmt"
	"time"
)

type IdentitySourceType string

const (
	LDAP    IdentitySourceType = "ldap"
	OIDC    IdentitySourceType = "oidc"
	LOCAL   IdentitySourceType = "local" // 本地口令认证源
	PASSKEY IdentitySourceType = "passkey"
)

func (i IdentitySourceType) String() string {
	return string(i)
}

// IdentitySource 身份源领域模型
type IdentitySource struct {
	ID            int64
	Name          string
	Type          IdentitySourceType
	LDAPConfig    LDAPConfig    // LDAP 专有配置
	OIDCConfig    OIDCConfig    `json:"oidc_config"`
	LocalConfig   LocalConfig   `json:"local_config"`
	PasskeyConfig PasskeyConfig `json:"passkey_config"`
	Enabled       bool          // 是否启用
	Ctime         time.Time
	Utime         time.Time
}

// OIDCProviderType OIDC 身份源的具体提供商类型
type OIDCProviderType string

const (
	OIDCProviderGeneric OIDCProviderType = "generic" // 通用 OIDC
	OIDCProviderFeishu  OIDCProviderType = "feishu"  // 飞书
	OIDCProviderWechat  OIDCProviderType = "wechat"  // 企业微信
)

// OIDCConfig OIDC 专有的配置结构
type OIDCConfig struct {
	Issuer       string           `json:"issuer"` // OIDC 提供商地址 e.g. https://open.feishu.cn/...
	ClientID     string           `json:"client_id"`
	ClientSecret string           `json:"client_secret"`
	RedirectURI  string           `json:"redirect_uri"`
	Scopes       []string         `json:"scopes"` // e.g. ["openid", "profile", "email"]
	UserInfoURL  string           `json:"user_info_url"`
	UserIDField  string           `json:"user_id_field"`
	ProviderType OIDCProviderType `json:"provider_type"` // 身份源提供商类型
	// 手动端点配置（飞书等非标准 OIDC 提供商使用，跳过 Discovery）
	AuthURL  string `json:"auth_url"`
	TokenURL string `json:"token_url"`

	JitEnabled bool `json:"jit_enabled"`

	// 属性映射 (用于 JIT 开户)
	Mapping Mapping `json:"mapping"`
}

type Mapping struct {
	Username string `json:"username"` // 映射到 Claims 中的哪个字段 e.g. "preferred_username"
	Email    string `json:"email"`    // e.g. "email"
}

// OidcIdentity OIDC 校验后提取的身份信息
type OidcIdentity struct {
	SourceID   int64
	SourceType IdentitySourceType // 来源类型：ldap / oidc
	Provider   string             // 具体身份源标识：feishu / wechat / generic
	ExternalID string             // sub
	Username   string
	Email      string
	RawClaims  map[string]interface{}
}

// LDAPConfig LDAP 专有的配置结构
type LDAPConfig struct {
	URL          string `json:"url"`
	BaseDN       string `json:"base_dn"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`

	// 属性映射
	UsernameAttribute    string `json:"username_attribute"`
	MailAttribute        string `json:"mail_attribute"`
	DisplayNameAttribute string `json:"display_name_attribute"`
	TitleAttribute       string `json:"title_attribute"`
	PhoneAttribute       string `json:"phone_attribute"`

	// 过滤条件
	UserFilter     string `json:"user_filter"`      // 用于登录/单人查询
	SyncUserFilter string `json:"sync_user_filter"` // 用于全量同步
}

// LocalConfig 本地口令专有的配置结构（口令策略）
type LocalConfig struct {
	MinLength         int  `json:"min_length"`          // 最小长度
	RequireDigit      bool `json:"require_digit"`       // 是否包含数字
	RequireUpper      bool `json:"require_upper"`       // 是否包含大写
	RequireLower      bool `json:"require_lower"`       // 是否包含小写
	RequireSymbol     bool `json:"require_symbol"`      // 是否包含特殊字符
	MaxFailedAttempts int  `json:"max_failed_attempts"` // 最大尝试次数（锁定）
	LockoutDuration   int  `json:"lockout_duration"`    // 锁定时间（分钟）
}

type PasskeyConfig struct {
	RPID                  string   `json:"rp_id"`
	RPName                string   `json:"rp_name"`
	RPOrigins             []string `json:"rp_origins"`
	AttestationPreference string   `json:"attestation_preference"`
	UserVerification      string   `json:"user_verification"`
}

// BuildUserIdentity 根据外部 OIDC 身份标识构建内部 UserIdentity
func (ident OidcIdentity) BuildUserIdentity() UserIdentity {
	id := UserIdentity{Provider: ident.Provider}
	switch ident.Provider {
	case SourceFeishu.String():
		id.FeishuInfo = FeishuInfo{
			UserID:  getClaimString(ident.RawClaims, "user_id"),
			UnionID: getClaimString(ident.RawClaims, "union_id"),
			OpenID:  getClaimString(ident.RawClaims, "open_id"),
		}
		id.IdentityID = id.FeishuInfo.UserID
	case SourceWechat.String():
		id.WechatInfo = WechatInfo{UserID: ident.ExternalID}
		id.IdentityID = ident.ExternalID
	default:
		id.IdentityID = ident.ExternalID
	}
	return id
}

func getClaimString(claims map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		v, ok := claims[key]
		if !ok || v == nil {
			continue
		}

		switch val := v.(type) {
		case string:
			if val != "" {
				return val
			}
		case fmt.Stringer:
			return val.String()
		default:
			return fmt.Sprint(val)
		}
	}

	return ""
}

// OAuthStateContext 记录 OAuth/OIDC 授权全生命周期中透传的业务上下文
type OAuthStateContext struct {
	StateID     string            `json:"state_id"`     // 防重放与防 CSRF 的唯一 State 随机值
	SourceID    int64             `json:"source_id"`    // 认证源 ID
	Nonce       string            `json:"nonce"`        // OIDC Nonce
	TenantID    int64             `json:"tenant_id"`    // 目标租户 ID（可选）
	RedirectURL string            `json:"redirect_url"` // 登录完成后需要恢复的深度业务页面（可选，如 /join?code=xxx）
	InviteCode  string            `json:"invite_code"`  // 邀请码（可选）
	Extra       map[string]string `json:"extra"`        // 扩展业务自定义键值对
	CreatedAt   int64             `json:"created_at"`   // 创建时间戳
}
