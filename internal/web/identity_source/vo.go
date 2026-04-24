package identity_source

import "time"

// SaveIdentitySourceReq 保存身份源请求
type SaveIdentitySourceReq struct {
	ID      int64  `json:"id"`
	Name    string `json:"name" binding:"required"`
	Type    string `json:"type" binding:"required"`
	Enabled bool   `json:"enabled"`

	// LDAP 专有配置
	LDAP *LDAPVO `json:"ldap"`
	// 未来可以扩展
	// OIDC *OIDCVO `json:"oidc"`
	// Feishu *FeishuVO `json:"feishu"`
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

	// 过滤条件
	UserFilter     string `json:"user_filter"`
	SyncUserFilter string `json:"sync_user_filter"`
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
	LDAP *LDAPVO `json:"ldap,omitempty"`
}
