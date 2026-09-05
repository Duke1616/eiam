package ldap

import (
	"context"
	"errors"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	idsource "github.com/Duke1616/eiam/internal/service/identity_source"
	"github.com/Duke1616/eiam/pkg/ldapx"
	"github.com/go-ldap/ldap/v3"
)

// DynamicLdapProvider 动态 LDAP 外部凭据认证提供者
type DynamicLdapProvider struct {
	idsSvc idsource.IService
}

// NewDynamicLdapProvider 创建动态 LDAP 凭据认证提供者
func NewDynamicLdapProvider(idsSvc idsource.IService) domain.CredentialProvider {
	return &DynamicLdapProvider{
		idsSvc: idsSvc,
	}
}

// Name 返回凭据提供者唯一标识
func (d *DynamicLdapProvider) Name() string {
	return domain.LDAP.String()
}

// Authenticate 核验 LDAP 用户名密码并组装为系统用户领域对象
func (d *DynamicLdapProvider) Authenticate(ctx context.Context, username, password string) (domain.User, error) {
	config, ok := getLDAPConfig(ctx, d.idsSvc)
	if !ok {
		return domain.User{}, errors.New("未找到启用的 LDAP 身份源配置")
	}

	client := newClient(config)
	filter := ldapx.ResolveUserFilter(config.UserFilter, username, config.UsernameAttribute, config.MailAttribute)
	entry, err := client.Authenticate(ctx, filter, password, getRequiredAttributes(config))
	if err != nil {
		return domain.User{}, err
	}

	return buildDomainUser(entry, config), nil
}

func getLDAPConfig(ctx context.Context, idsSvc idsource.IService) (domain.LDAPConfig, bool) {
	source, err := idsSvc.FindEnabled(ctx, domain.LDAP)
	if err != nil {
		return domain.LDAPConfig{}, false
	}
	return source.LDAPConfig, true
}

func newClient(cfg domain.LDAPConfig) ldapx.IClient {
	return ldapx.NewClient(ldapx.Config{
		URL:          cfg.URL,
		BaseDN:       cfg.BaseDN,
		BindDN:       cfg.BindDN,
		BindPassword: cfg.BindPassword,
	})
}

func getRequiredAttributes(cfg domain.LDAPConfig) []string {
	return []string{
		"dn",
		cfg.MailAttribute,
		cfg.UsernameAttribute,
		cfg.DisplayNameAttribute,
		cfg.TitleAttribute,
		cfg.PhoneAttribute,
	}
}

func buildDomainUser(entry *ldap.Entry, cfg domain.LDAPConfig) domain.User {
	u := domain.User{
		Status: domain.StatusActive,
		Source: domain.SourceLdap,
		Identities: []domain.UserIdentity{
			{
				Provider:   domain.LDAP.String(),
				IdentityID: entry.DN,
				LdapInfo:   domain.LdapInfo{DN: entry.DN},
			},
		},
	}

	for _, attr := range entry.Attributes {
		val := ""
		if len(attr.Values) > 0 {
			val = attr.Values[0]
		}

		name := attr.Name
		switch {
		case strings.EqualFold(name, cfg.UsernameAttribute):
			u.Username = val
		case strings.EqualFold(name, cfg.MailAttribute):
			u.Email = val
		case strings.EqualFold(name, cfg.DisplayNameAttribute):
			u.Profile.Nickname = val
		case strings.EqualFold(name, cfg.TitleAttribute):
			u.Profile.JobTitle = val
		case strings.EqualFold(name, cfg.PhoneAttribute):
			u.Profile.Phone = val
		}
	}
	return u
}
