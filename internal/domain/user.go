package domain

import "context"

type Status uint8

const (
	StatusUnknown Status = 0
	StatusActive  Status = 1
	StatusDisable Status = 2
)

func (s Status) String() string {
	switch s {
	case StatusActive:
		return "active"
	case StatusDisable:
		return "disable"
	default:
		return "unknown"
	}
}

func ParseStatus(s string) Status {
	switch s {
	case "active":
		return StatusActive
	case "disable":
		return StatusDisable
	default:
		return StatusUnknown
	}
}

type Source string

const (
	SourceLocal  Source = "local"
	SourceLdap   Source = "ldap"
	SourceFeishu Source = "feishu"
	SourceWechat Source = "wechat"
)

func (s Source) String() string {
	return string(s)
}

// User 全局主账户
type User struct {
	ID          int64
	Username    string
	Password    string
	Email       string
	Status      Status
	Source      Source
	MfaType     string
	MfaSecret   string
	Ctime       int64
	Utime       int64
	LastLoginAt int64

	// 各司其职：侧写资料归公司
	Profile UserProfile
	// 一表通行：身份标识归个人
	Identities []UserIdentity
}

// UserProfile 业务名片
type UserProfile struct {
	UserID   int64
	Nickname string
	Avatar   string
	JobTitle string
	Phone    string
}

// UserIdentity 全球身份标记：与租户彻底脱钩
type UserIdentity struct {
	ID         int64
	UserID     int64  // 唯一锚点：这是谁的身份？
	Provider   string // 来源：微信、飞书、passkey 等
	IdentityID string // 核心标识符：DN, OpenID, CredentialID(base64)

	LdapInfo    LdapInfo
	FeishuInfo  FeishuInfo
	WechatInfo  WechatInfo
	PasskeyInfo PasskeyInfo
}

type PasskeyInfo struct {
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte
	SignCount       uint32
	BackupEligible  bool
	BackupState     bool
	Nickname        string
}

func (u User) GetPrimaryIdentity(provider string) (UserIdentity, bool) {
	for _, id := range u.Identities {
		if id.Provider == provider {
			return id, true
		}
	}
	return UserIdentity{}, false
}

func (id UserIdentity) IdentityKey() string {
	if id.IdentityID != "" {
		return id.IdentityID
	}

	switch id.Provider {
	case "ldap":
		return id.LdapInfo.DN
	case "feishu":
		return id.FeishuInfo.UserID
	case "wechat":
		return id.WechatInfo.UserID
	default:
		return ""
	}
}

type LdapInfo struct {
	DN string
}

type WechatInfo struct {
	UserID string
}

type FeishuInfo struct {
	OpenID  string `json:"open_id"`
	UnionID string `json:"union_id"`
	UserID  string `json:"user_id"`
}

// LoginResult 登录结果：封装认证后的用户信息与可用租户空间
// TenantID != 0 → 单租户，直接颁发正式 JWT
// TenantID == 0 → 多租户，前端从 Tenants 列表选择后调 SwitchTenant
type LoginResult struct {
	User     User
	TenantID int64
	Tenants  []Tenant
	AuthType string `json:"auth_type"` // 本次登录成功所使用的真实认证方式 (local, ldap, oidc, passkey 等)

	// MFA/Passkey 流程支持
	MfaRequired bool   `json:"mfa_required"`
	MfaToken    string `json:"mfa_token"`

	MustSelectTenant bool   `json:"must_select_tenant"`
	MustBind         bool   `json:"must_bind"`
	BindToken        string `json:"bind_token"`
}

// CredentialProvider 外部凭证提供者策略接口。
type CredentialProvider interface {
	// Name 返回身份源唯一标识 (ldap 等)
	Name() string
	// Authenticate 执行外部身份核验，返回构造完毕的领域用户模型
	Authenticate(ctx context.Context, username, password string) (User, error)
}
