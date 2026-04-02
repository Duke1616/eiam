package user

import (
	"context"
)

// ExternalProfile 定义来自于外部身份源的标准资料对象 (如 LDAP 或飞书返回的数据)
type ExternalProfile struct {
	ExternalID string            // 外部系统中的唯一物理标识 (如 LDAP 的 DN, 飞书的 open_id)
	Username   string            // 外部系统账号名 (用于本地建号建议)
	Email      string            // 用户邮箱 (若有)
	Nickname   string            // 用户显示名/昵称
	JobTitle   string            // 职位/职称
	Extra      map[string]string // 其它身份源特有的扩展属性 (映射为本地 Profile Metadata)
}

// IdentityProvider 联邦身份源标准接口：实现该接口即视为接入 eiam 认证体系
type IdentityProvider interface {
	// Name 返回身份协议标识名 (如 "ldap", "feishu", "wechat")
	Name() string
	// Authenticate 执行外部认证逻辑，并返回标准外部资料
	Authenticate(ctx context.Context, username, password string) (ExternalProfile, error)
}
