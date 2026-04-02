package user

import (
	"github.com/Duke1616/eiam/internal/domain"
)

// SignupRequest 注册请求：账号 + 基础详情资料
type SignupRequest struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	Email           string `json:"email"`

	// 以下属 Profile 名片板块
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	JobTitle string `json:"job_title"`
}

func (req SignupRequest) ToDomain() domain.User {
	return domain.User{
		Username: req.Username,
		Password: req.Password,
		Email:    req.Email,
		Profile: domain.UserInfo{
			Nickname: req.Nickname,
			Avatar:   req.Avatar,
			JobTitle: req.JobTitle,
		},
	}
}

// LoginLdapRequest LDAP 登录专用请求
type LoginLdapRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginSystemRequest 系统本地登录专用请求
type LoginSystemRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UserVO 统一用户展示对象：前端脱敏展示
type UserVO struct {
	ID        int64             `json:"id"`
	Username  string            `json:"username"`
	Email     string            `json:"email"`
	Nickname  string            `json:"nickname"`
	Avatar    string            `json:"avatar"`
	JobTitle  string            `json:"job_title"`
	Metadata  map[string]string `json:"metadata"`
	// Identities 列表展示关联的各平台标识
	Identities []IdentityVO `json:"identities"`
}

type IdentityVO struct {
	Provider   string `json:"provider"`
	ExternalID string `json:"external_id"`
}

func ToUserVO(u domain.User) UserVO {
	identities := make([]IdentityVO, 0, len(u.Identities))
	for _, id := range u.Identities {
		identities = append(identities, IdentityVO{
			Provider:   id.Provider,
			ExternalID: id.ExternalID,
		})
	}

	return UserVO{
		ID:         u.ID,
		Username:   u.Username,
		Email:      u.Email,
		Nickname:   u.Profile.Nickname,
		Avatar:     u.Profile.Avatar,
		JobTitle:   u.Profile.JobTitle,
		Metadata:   u.Profile.Metadata,
		Identities: identities, // 补全 Identities 展示
	}
}

type UpdateUserReq struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	JobTitle string `json:"job_title"`
}

type FindByKeywordReq struct {
	Page
	Keyword string `json:"keyword"`
}

type FindByUserNameReq struct {
	Username string `json:"username"`
}

type UserBindRoleReq struct {
	ID        int64    `json:"id"`
	RoleCodes []string `json:"role_codes"`
}

type Page struct {
	Offset int64 `json:"offset,omitempty"`
	Limit  int64 `json:"limit,omitempty"`
}

type RetrieveUsers struct {
	Total int64    `json:"total"`
	Users []UserVO `json:"users"`
}
