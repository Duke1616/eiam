package user

import (
	"github.com/Duke1616/eiam/internal/domain"
)

// SignupRequest 注册请求
type SignupRequest struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	Email           string `json:"email"`

	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	JobTitle string `json:"job_title"`
}

func (req SignupRequest) ToDomain() domain.User {
	return domain.User{
		Username: req.Username,
		Password: req.Password,
		Email:    req.Email,
		Profile: domain.UserProfile{
			Nickname: req.Nickname,
			Avatar:   req.Avatar,
			JobTitle: req.JobTitle,
		},
	}
}

// LoginLdapRequest LDAP 登录请求
type LoginLdapRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginSystemRequest 本地登录请求
type LoginSystemRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// SwitchTenantRequest 空间切换请求
type SwitchTenantRequest struct {
	TenantID int64 `json:"tenant_id"`
}

// UserVO 用户展示对象
type UserVO struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	JobTitle string `json:"job_title"`

	Identities []IdentityVO `json:"identities"`
}

type IdentityVO struct {
	Provider   string            `json:"provider"`
	LdapInfo   domain.LdapInfo   `json:"ldap_info,omitempty"`
	WechatInfo domain.WechatInfo `json:"wechat_info,omitempty"`
	FeishuInfo domain.FeishuInfo `json:"feishu_info,omitempty"`
}

func ToUserVO(u domain.User) UserVO {
	identities := make([]IdentityVO, 0, len(u.Identities))
	for _, id := range u.Identities {
		identities = append(identities, IdentityVO{
			Provider:   id.Provider,
			LdapInfo:   id.LdapInfo,
			WechatInfo: id.WechatInfo,
			FeishuInfo: id.FeishuInfo,
		})
	}

	return UserVO{
		ID:         u.ID,
		Username:   u.Username,
		Email:      u.Email,
		Nickname:   u.Profile.Nickname,
		Avatar:     u.Profile.Avatar,
		JobTitle:   u.Profile.JobTitle,
		Identities: identities,
	}
}

// TenantVO 空间展示对象
type TenantVO struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Code   string `json:"code"`
	Domain string `json:"domain"`
}

func ToTenantVOs(ts []domain.Tenant) []TenantVO {
	res := make([]TenantVO, 0, len(ts))
	for _, t := range ts {
		res = append(res, TenantVO{
			ID:     t.ID,
			Name:   t.Name,
			Code:   t.Code,
			Domain: t.Domain,
		})
	}
	return res
}

type UpdateUserReq struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	JobTitle string `json:"job_title"`
}

type RetrieveUsers struct {
	Total int64    `json:"total"`
	Users []UserVO `json:"users"`
}

type RetrieveUser struct {
	User    UserVO     `json:"user"`
	Tenants []TenantVO `json:"tenants"`
}
