package domain

import (
	"time"
)

type Status int

const (
	StatusActive Status = 1
)

type User struct {
	ID        int64
	Username  string
	Password  string
	Email     string
	Status    Status
	TenantID  int64
	CreatedAt time.Time
	UpdatedAt time.Time

	// 核心关联属性
	Profile    UserInfo       // 用户详细名片
	Identities []UserIdentity // 关联的所有联邦身份 (LDAP, Feishu, Wechat...)
}

// GetExternalID 快捷工具：快速获取指定身份源的外部 ID（如发送通知时获取飞书 ID）
func (u User) GetExternalID(provider string) string {
	for _, identity := range u.Identities {
		if identity.Provider == provider {
			return identity.ExternalID
		}
	}
	return ""
}

type UserInfo struct {
	Nickname string
	Avatar   string
	JobTitle string
	Metadata map[string]string // 存放非唯一、松散的元数据
}

type UserIdentity struct {
	ID         int64
	UserID     int64
	Provider   string            // 身份源名称: "ldap", "feishu", "wechat"
	ExternalID string            // 外部唯一标识: "fs_12345", "uid-abc"
	Extra      map[string]string // 存放该身份源特有的原始 JSON 数据
}
