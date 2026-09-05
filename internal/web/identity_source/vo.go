package identity_source

import "time"

// SaveIdentitySourceReq 保存身份源请求
type SaveIdentitySourceReq struct {
	ID      int64  `json:"id"`
	Name    string `json:"name" binding:"required"`
	Type    string `json:"type" binding:"required"`
	Enabled bool   `json:"enabled"`

	// LDAP 专有配置
	LDAP    *LDAPVO    `json:"ldap"`
	OIDC    *OIDCVO    `json:"oidc"`
	Local   *LocalVO   `json:"local"`
	Passkey *PasskeyVO `json:"passkey"`
}

// LDAPVO LDAP 配置视图对象
type LDAPVO struct {
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
	UserFilter     string `json:"user_filter"`
	SyncUserFilter string `json:"sync_user_filter"`
}

type OIDCVO struct {
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	RedirectURI  string    `json:"redirect_uri"`
	Scopes       []string  `json:"scopes"`
	UserInfoURL  string    `json:"user_info_url"`
	UserIDField  string    `json:"user_id_field"`
	ProviderType string    `json:"provider_type"` // feishu / wechat / generic
	AuthURL      string    `json:"auth_url"`      // 手动授权端点（跳过 Discovery）
	TokenURL     string    `json:"token_url"`     // 手动 Token 端点（跳过 Discovery）
	Mapping      MappingVO `json:"mapping"`
}

type LocalVO struct {
	MinLength         int  `json:"min_length"`
	RequireDigit      bool `json:"require_digit"`
	RequireUpper      bool `json:"require_upper"`
	RequireLower      bool `json:"require_lower"`
	RequireSymbol     bool `json:"require_symbol"`
	MaxFailedAttempts int  `json:"max_failed_attempts"`
	LockoutDuration   int  `json:"lockout_duration"`
}

type MappingVO struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

// IdentitySourceVO 身份源响应视图对象
type IdentitySourceVO struct {
	ID      int64     `json:"id"`
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	Enabled bool      `json:"enabled"`
	Ctime   time.Time `json:"ctime"`
	Utime   time.Time `json:"utime"`

	// 根据 Type 返回对应的配置
	LDAP    *LDAPVO    `json:"ldap,omitempty"`
	OIDC    *OIDCVO    `json:"oidc,omitempty"`
	Local   *LocalVO   `json:"local,omitempty"`
	Passkey *PasskeyVO `json:"passkey,omitempty"`
}

type PasskeyVO struct {
	RPID                  string   `json:"rp_id"`
	RPName                string   `json:"rp_name"`
	RPOrigins             []string `json:"rp_origins"`
	AttestationPreference string   `json:"attestation_preference"`
	UserVerification      string   `json:"user_verification"`
}
