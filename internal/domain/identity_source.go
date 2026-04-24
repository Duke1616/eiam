package domain

import "time"

type IdentitySourceType string

const (
	LDAP IdentitySourceType = "ldap"
	OIDC IdentitySourceType = "oidc"
)

// IdentitySource 身份源领域模型
type IdentitySource struct {
	ID         int64
	Name       string
	Type       IdentitySourceType
	LDAPConfig LDAPConfig // LDAP 专有配置
	Enabled    bool       // 是否启用
	Ctime      time.Time
	Utime      time.Time
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

	// 过滤条件
	UserFilter     string `json:"user_filter"`      // 用于登录/单人查询
	SyncUserFilter string `json:"sync_user_filter"` // 用于全量同步
}
