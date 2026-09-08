package idp

import (
	"time"

	"github.com/Duke1616/eiam/internal/domain"
)

// CreateApplicationReq 创建应用请求
type CreateApplicationReq struct {
	Name          string   `json:"name" binding:"required"`
	Protocol      string   `json:"protocol"`  // 接入协议类型: oidc / cas / saml (默认 oidc)
	ClientID      string   `json:"client_id"` // 可选，留空由服务端自动生成
	Logo          string   `json:"logo"`
	RedirectURIs  []string `json:"redirect_uris" binding:"required"` // 至少一个合法回调地址
	ResponseTypes []string `json:"response_types"`
	GrantTypes    []string `json:"grant_types"`
	Scopes        []string `json:"scopes"`
	IsPublic      bool     `json:"is_public"`
	AutoConsent   bool     `json:"auto_consent"` // 是否跳过用户授权确认 (第一方应用建议设为 true)
}

// UpdateApplicationReq 更新应用请求
type UpdateApplicationReq struct {
	ID            int64    `json:"id" binding:"required"`
	Name          string   `json:"name" binding:"required"`
	Protocol      string   `json:"protocol"`
	Logo          string   `json:"logo"`
	RedirectURIs  []string `json:"redirect_uris" binding:"required"`
	ResponseTypes []string `json:"response_types"`
	GrantTypes    []string `json:"grant_types"`
	Scopes        []string `json:"scopes"`
	IsPublic      bool     `json:"is_public"`
	AutoConsent   bool     `json:"auto_consent"`
}

func (r UpdateApplicationReq) ToDomain() domain.Application {
	protocol := domain.Protocol(r.Protocol)
	if protocol == "" {
		protocol = domain.ProtocolOIDC
	}
	return domain.Application{
		ID:            r.ID,
		Name:          r.Name,
		Protocol:      protocol,
		Logo:          r.Logo,
		RedirectURIs:  r.RedirectURIs,
		ResponseTypes: r.ResponseTypes,
		GrantTypes:    r.GrantTypes,
		Scopes:        r.Scopes,
		IsPublic:      r.IsPublic,
		AutoConsent:   r.AutoConsent,
	}
}

// ListApplicationReq 应用分页查询请求
type ListApplicationReq struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

// ApplicationVO 应用视图响应对象
type ApplicationVO struct {
	ID            int64     `json:"id"`
	TenantID      int64     `json:"tenant_id"`
	Protocol      string    `json:"protocol"`
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
