package user

import "github.com/Duke1616/eiam/internal/domain"

// BaseUserRequest 用户基础信息请求
type BaseUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	JobTitle string `json:"job_title"`
	Phone    string `json:"phone"`
	Status   string `json:"status"`
}

// SignupRequest 注册请求
type SignupRequest struct {
	BaseUserRequest
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

// LoginRequest 登录请求（适用于 LDAP 和本地登录）
type LoginRequest struct {
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
	Status      string `json:"status"`
	Source      string `json:"source"`
	Ctime       int64  `json:"ctime"`
	Utime       int64  `json:"utime"`
	LastLoginAt int64  `json:"last_login_at"`

	MfaType    string     `json:"mfa_type"`
	MfaBound   bool       `json:"mfa_bound"`
	Identities []Identity `json:"identities"`
}

// UserMemberVO 组合了用户基础信息与当前租户的成员状态
// 用于在用户列表/详情中展示该用户与当前查看租户的关系
type UserMemberVO struct {
	User
	// IsMember 表示该用户是否已入驻当前查看的租户（tenant_id 来自请求上下文）。
	// 注意：批量查询(List)时依赖 memberMap 的转换，若用户在多个租户中有入驻关系，
	// map[int64]Membership 只会保留最后一条记录，可能导致 IsMember 判断错误。
	IsMember *bool `json:"is_member,omitempty"`

	// 是不是在系统租户下
	IsSystemSpace bool `json:"is_system_space"`
}

type Identity struct {
	Provider    string      `json:"provider"`
	LdapInfo    LdapInfo    `json:"ldap_info,omitempty"`
	WechatInfo  WechatInfo  `json:"wechat_info,omitempty"`
	FeishuInfo  FeishuInfo  `json:"feishu_info,omitempty"`
	PasskeyInfo PasskeyInfo `json:"passkey_info,omitempty"`
}

type LdapInfo struct {
	DN string `json:"dn"`
}

type WechatInfo struct {
	UserID string `json:"user_id"`
}

type FeishuInfo struct {
	OpenID  string `json:"open_id"`
	UnionID string `json:"union_id"`
	UserID  string `json:"user_id"`
}

type PasskeyLoginFinishRequest struct {
	Credential any `json:"credential"`
}

type PasskeyRegisterFinishRequest struct {
	Credential any `json:"credential"`
}

// Tenant 空间展示对象
type Tenant struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Code   string `json:"code"`
	Domain string `json:"domain"`
}

type BatchDeleteReq struct {
	IDs []int64 `json:"ids" binding:"required"`
}

type UpdateUserReq struct {
	ID int64 `json:"id"`
	BaseUserRequest
}

type RetrieveUsers[T any] struct {
	Total int64 `json:"total"`
	Users []T   `json:"users"`
}

type RetrieveUser struct {
	User             User     `json:"user"`
	Tenants          []Tenant `json:"tenants"`
	CurrentTenantID  int64    `json:"current_tenant_id"`
	MustSelectTenant bool     `json:"must_select_tenant"`
	MustBind         bool     `json:"must_bind"`
	BindToken        string   `json:"bind_token,omitempty"`
	MfaRequired      bool     `json:"mfa_required"`
	MfaToken         string   `json:"mfa_token,omitempty"`
	IsAdmin          bool     `json:"is_admin"`
	Permissions      []string `json:"permissions"`
}

type UpdatePasswordRequest struct {
	OldPassword     string `json:"old_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

// BaseListRequest 分页列表请求
type BaseListRequest struct {
	Offset  int64  `json:"offset"`
	Limit   int64  `json:"limit"`
	Keyword string `json:"keyword"`
}

type ListUserRequest struct {
	BaseListRequest
}

type SearchLdapUser struct {
	Keywords string `json:"keywords"`
	Offset   int    `json:"offset"`
	Limit    int    `json:"limit"`
}

type ListRoleUsersRequest struct {
	RoleCode string `json:"role_code"`
	BaseListRequest
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
	UserID     int64  `json:"user_id"`
	Provider   string `json:"provider"`
	IdentityID string `json:"identity_id"`
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

type IdentityVo struct {
	Provider    string      `json:"provider"`
	IdentityID  string      `json:"identity_id"`
	PasskeyInfo PasskeyInfo `json:"passkey_info,omitempty"`
}

type PasskeyInfo struct {
	SignCount      uint32 `json:"sign_count"`
	BackupEligible bool   `json:"backup_eligible"`
	BackupState    bool   `json:"backup_state"`
	Nickname       string `json:"nickname"`
}

type MfaTotpSetupResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qrcode_url"`
}

type MfaTotpBindRequest struct {
	Code   string `json:"code"`
	Secret string `json:"secret"`
}

type ContinueLoginRequest struct {
	SessionID   string         `json:"session_id"`
	CurrentStep string         `json:"current_step"`
	Data        map[string]any `json:"data"`
}

type MfaLoginVerifyRequest struct {
	MfaToken string `json:"mfa_token"`
	Code     string `json:"code"`
}
