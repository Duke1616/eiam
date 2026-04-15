package domain

type Status int

const (
	StatusActive Status = 1
)

// User 全局主账户
type User struct {
	ID       int64
	Username string
	Password string
	Email    string
	Status   Status
	Ctime    int64
	Utime    int64

	// 各司其职：侧写资料归公司
	Profile    UserProfile
	// 一表通行：身份标识归个人
	Identities []UserIdentity
}

// UserProfile 业务名片
type UserProfile struct {
	UserID   int64
	Nickname string
	Avatar   string
	JobTitle string
}

// UserIdentity 全球身份标记：与租户彻底脱钩
type UserIdentity struct {
	ID       int64
	UserID   int64  // 唯一锚点：这是谁的身份？
	Provider string // 来源：微信、飞书等
	
	LdapInfo   LdapInfo
	FeishuInfo FeishuInfo
	WechatInfo WechatInfo
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
	OpenID string
	UserID string
}

// LoginResult 登录结果：封装认证后的用户信息与可用租户空间
// TenantID != 0 → 单租户，直接颁发正式 JWT
// TenantID == 0 → 多租户，前端从 Tenants 列表选择后调 SwitchTenant
type LoginResult struct {
	User     User
	TenantID int64
	Tenants  []Tenant
}
