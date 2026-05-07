package identity_source

import (
	"fmt"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
)

// mapper 根据 ProviderType 返回相应的 mapper 实现
func (c *oidcClient) mapper() oidcIdentityMapper {
	switch c.conf.ProviderType {
	case domain.OIDCProviderFeishu:
		return feishuIdentityMapper{conf: c.conf}
	case domain.OIDCProviderWechat:
		return wechatIdentityMapper{conf: c.conf}
	default:
		return defaultIdentityMapper{conf: c.conf}
	}
}

type oidcIdentityMapper interface {
	Map(sourceID int64, claims map[string]interface{}) (domain.OidcIdentity, error)
}

type defaultIdentityMapper struct {
	conf domain.OIDCConfig
}

func (m defaultIdentityMapper) Map(sourceID int64, claims map[string]interface{}) (domain.OidcIdentity, error) {
	username := firstNonEmptyString(claims,
		m.conf.Mapping.Username,
		"preferred_username",
		"name",
		"display_name",
		"sub",
	)
	email := firstNonEmptyString(claims, m.conf.Mapping.Email, "email")
	externalID := firstNonEmptyString(claims, m.conf.UserIDField, "sub", "user_id", "open_id", "union_id")
	if externalID == "" {
		return domain.OidcIdentity{}, fmt.Errorf("OIDC 身份信息缺失唯一标识")
	}
	if username == "" {
		username = externalID
	}

	return domain.OidcIdentity{
		SourceID:   sourceID,
		ExternalID: externalID,
		Username:   username,
		Email:      email,
		RawClaims:  claims,
	}, nil
}

type feishuIdentityMapper struct {
	conf domain.OIDCConfig
}

func (m feishuIdentityMapper) Map(sourceID int64, claims map[string]interface{}) (domain.OidcIdentity, error) {
	username := firstNonEmptyString(claims,
		m.conf.Mapping.Username,
		"name",
		"en_name",
		"display_name",
		"open_id",
		"union_id",
		"sub",
	)
	email := firstNonEmptyString(claims, m.conf.Mapping.Email, "email")
	externalID := firstNonEmptyString(claims, m.conf.UserIDField, "sub", "user_id", "union_id", "open_id")
	if externalID == "" {
		return domain.OidcIdentity{}, fmt.Errorf("飞书 OIDC 身份信息缺失唯一标识")
	}
	if username == "" {
		username = externalID
	}

	return domain.OidcIdentity{
		SourceID:   sourceID,
		ExternalID: externalID,
		Username:   username,
		Email:      email,
		RawClaims:  claims,
	}, nil
}

// wechatIdentityMapper 企业微信身份映射
type wechatIdentityMapper struct {
	conf domain.OIDCConfig
}

func (m wechatIdentityMapper) Map(sourceID int64, claims map[string]interface{}) (domain.OidcIdentity, error) {
	username := firstNonEmptyString(claims,
		m.conf.Mapping.Username,
		"nickname",
		"userid",
		"name",
		"sub",
	)
	email := firstNonEmptyString(claims, m.conf.Mapping.Email, "email")
	externalID := firstNonEmptyString(claims, m.conf.UserIDField, "userid", "sub", "open_userid")
	if externalID == "" {
		return domain.OidcIdentity{}, fmt.Errorf("企业微信 OIDC 身份信息缺失唯一标识")
	}
	if username == "" {
		username = externalID
	}

	return domain.OidcIdentity{
		SourceID:   sourceID,
		ExternalID: externalID,
		Username:   username,
		Email:      email,
		RawClaims:  claims,
	}, nil
}

// resolveProviderName 根据配置解析身份源标识，用于绑定 UserIdentity
func resolveProviderName(conf domain.OIDCConfig) string {
	switch conf.ProviderType {
	case domain.OIDCProviderFeishu:
		return string(domain.SourceFeishu)
	case domain.OIDCProviderWechat:
		return string(domain.SourceWechat)
	default:
		return "oidc"
	}
}

func firstNonEmptyString(values map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		val, ok := values[key]
		if !ok {
			continue
		}
		str, ok := val.(string)
		if ok && str != "" {
			return str
		}
	}
	return ""
}
