package user

import "github.com/Duke1616/eiam/internal/domain"

// SignupRequest 注册请求
type SignupRequest struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	Email           string `json:"email"`
	Nickname        string `json:"nickname"`
	Avatar          string `json:"avatar"`
	JobTitle        string `json:"job_title"`
	Phone           string `json:"phone"`
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

// User 用户展示对象
type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Nickname    string `json:"nickname"`
	Avatar      string `json:"avatar"`
	JobTitle    string `json:"job_title"`
	Phone       string `json:"phone"`
	Source      string `json:"source"`
	Ctime       int64  `json:"ctime"`
	Utime       int64  `json:"utime"`
	LastLoginAt int64  `json:"last_login_at"`

	Identities []Identity `json:"identities"`
}

// UserMemberVO 组合了用户基础信息与当前租户的成员状态
type UserMemberVO struct {
	User
	IsMember      *bool `json:"is_member,omitempty"`
	IsSystemSpace bool  `json:"is_system_space,omitempty"`
}

type Identity struct {
	Provider   string     `json:"provider"`
	LdapInfo   LdapInfo   `json:"ldap_info,omitempty"`
	WechatInfo WechatInfo `json:"wechat_info,omitempty"`
	FeishuInfo FeishuInfo `json:"feishu_info,omitempty"`
}

type LdapInfo struct {
	DN string `json:"dn"`
}

type WechatInfo struct {
	UserID string `json:"user_id"`
}

type FeishuInfo struct {
	OpenID string `json:"open_id"`
	UserID string `json:"user_id"`
}

// Tenant 空间展示对象
type Tenant struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Code   string `json:"code"`
	Domain string `json:"domain"`
}

type UpdateUserReq struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	JobTitle string `json:"job_title"`
	Phone    string `json:"phone"`
}

type RetrieveUsers[T any] struct {
	Total int64 `json:"total"`
	Users []T   `json:"users"`
}

type RetrieveUser struct {
	User             User     `json:"user"`
	Tenants          []Tenant `json:"tenants"`
	MustSelectTenant bool     `json:"must_select_tenant"`
}

type UpdatePasswordRequest struct {
	OldPassword     string `json:"old_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

type ListUserRequest struct {
	Offset  int64  `json:"offset"`
	Limit   int64  `json:"limit"`
	Keyword string `json:"keyword"`
}

type SearchLdapUser struct {
	Keywords string `json:"keywords"`
	Offset   int    `json:"offset"`
	Limit    int    `json:"limit"`
}

type ListRoleUsersRequest struct {
	RoleCode string `json:"role_code"`
	Offset   int64  `json:"offset"`
	Limit    int64  `json:"limit"`
	Keyword  string `json:"keyword"`
}

type SyncLdapUserReq struct {
	Users []User `json:"users"`
}

type BindIdentityRequest struct {
	UserID     int64      `json:"user_id"`
	Provider   string     `json:"provider"`
	LdapInfo   LdapInfo   `json:"ldap_info"`
	WechatInfo WechatInfo `json:"wechat_info"`
	FeishuInfo FeishuInfo `json:"feishu_info"`
}

func (req BindIdentityRequest) ToDomain() domain.UserIdentity {
	return domain.UserIdentity{
		UserID:     req.UserID,
		Provider:   req.Provider,
		LdapInfo:   domain.LdapInfo(req.LdapInfo),
		WechatInfo: domain.WechatInfo(req.WechatInfo),
		FeishuInfo: domain.FeishuInfo(req.FeishuInfo),
	}
}

type UnbindIdentityRequest struct {
	UserID   int64  `json:"user_id"`
	Provider string `json:"provider"`
}

type ManageIdentitiesRequest struct {
	UserID     int64      `json:"user_id"`
	LdapInfo   LdapInfo   `json:"ldap_info"`
	WechatInfo WechatInfo `json:"wechat_info"`
	FeishuInfo FeishuInfo `json:"feishu_info"`
}

type LdapSyncUser struct {
	User
	IsSynced bool `json:"is_synced"`
}

type LdapUserList struct {
	Total int64          `json:"total"`
	Users []LdapSyncUser `json:"users"`
}

type SwitchTenantRequest struct {
	TenantID int64 `json:"tenant_id"`
}

type UserVO struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Status   uint8  `json:"status"`
	Source   string `json:"source"`
}
