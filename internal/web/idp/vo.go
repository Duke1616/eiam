package idp

import "time"

// CreateOAuthClientReq 创建应用请求
type CreateOAuthClientReq struct {
	Name          string   `json:"name" binding:"required"`
	ClientID      string   `json:"client_id"` // 可选，留空由服务端自动生成
	Logo          string   `json:"logo"`
	RedirectURIs  []string `json:"redirect_uris" binding:"required"` // 至少一个合法回调地址
	ResponseTypes []string `json:"response_types"`
	GrantTypes    []string `json:"grant_types"`
	Scopes        []string `json:"scopes"`
	IsPublic      bool     `json:"is_public"`
	AutoConsent   bool     `json:"auto_consent"` // 是否跳过用户授权确认 (第一方应用建议设为 true)
}

// UpdateOAuthClientReq 更新应用请求
type UpdateOAuthClientReq struct {
	ID            int64    `json:"id" binding:"required"`
	Name          string   `json:"name" binding:"required"`
	Logo          string   `json:"logo"`
	RedirectURIs  []string `json:"redirect_uris" binding:"required"`
	ResponseTypes []string `json:"response_types"`
	GrantTypes    []string `json:"grant_types"`
	Scopes        []string `json:"scopes"`
	IsPublic      bool     `json:"is_public"`
	AutoConsent   bool     `json:"auto_consent"`
}

// ListOAuthClientReq 应用分页查询请求
type ListOAuthClientReq struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

// OAuthClientVO 应用视图响应对象
type OAuthClientVO struct {
	ID            int64     `json:"id"`
	TenantID      int64     `json:"tenant_id"`
	ClientID      string    `json:"client_id"`
	ClientSecret  string    `json:"client_secret,omitempty"` // 仅在创建或重置时呈现
	Name          string    `json:"name"`
	Logo          string    `json:"logo"`
	RedirectURIs  []string  `json:"redirect_uris"`
	ResponseTypes []string  `json:"response_types"`
	GrantTypes    []string  `json:"grant_types"`
	Scopes        []string  `json:"scopes"`
	IsPublic      bool      `json:"is_public"`
	AutoConsent   bool      `json:"auto_consent"`
	Ctime         time.Time `json:"ctime"`
	Utime         time.Time `json:"utime"`
}

// ResetSecretResp 重置密钥响应对象
type ResetSecretResp struct {
	ClientSecret string `json:"client_secret"`
}

// ConfirmConsentReq 提交授权确认请求
type ConfirmConsentReq struct {
	ConsentID string `json:"consent_id" form:"consent_id" binding:"required"`
	Approved  bool   `json:"approved" form:"approved"` // true: 同意授权; false: 拒绝
}
