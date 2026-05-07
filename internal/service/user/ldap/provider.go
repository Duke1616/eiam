package ldap

import (
	"context"
	"errors"

	"github.com/Duke1616/eiam/internal/domain"
	idsource "github.com/Duke1616/eiam/internal/service/identity_source"
	"github.com/Duke1616/eiam/internal/service/user/ldapx"
	"github.com/ecodeclub/ekit/slice"
)

type DynamicLdapProvider struct {
	idsSvc idsource.IService
}

func NewDynamicLdapProvider(idsSvc idsource.IService) domain.CredentialProvider {
	return &DynamicLdapProvider{
		idsSvc: idsSvc,
	}
}

func (d *DynamicLdapProvider) Name() string {
	return "ldap"
}

func (d *DynamicLdapProvider) Authenticate(ctx context.Context, username, password string) (domain.User, error) {
	config, ok := d.getLDAPConfig(ctx)
	if !ok {
		return domain.User{}, errors.New("未找到启用的 LDAP 身份源配置")
	}

	provider := ldapx.NewLdap(d.toLdapxConfig(config))
	return provider.Authenticate(ctx, username, password)
}

func (d *DynamicLdapProvider) getLDAPConfig(ctx context.Context) (domain.LDAPConfig, bool) {
	sources, err := d.idsSvc.List(ctx)
	if err != nil {
		return domain.LDAPConfig{}, false
	}

	config, found := slice.Find(sources, func(src domain.IdentitySource) bool {
		return src.Type == domain.LDAP && src.Enabled
	})

	if !found {
		return domain.LDAPConfig{}, false
	}

	return config.LDAPConfig, true
}

func (d *DynamicLdapProvider) toLdapxConfig(cfg domain.LDAPConfig) ldapx.Config {
	return ldapx.Config{
		Url:                  cfg.URL,
		BaseDN:               cfg.BaseDN,
		BindDN:               cfg.BindDN,
		BindPassword:         cfg.BindPassword,
		UsernameAttribute:    cfg.UsernameAttribute,
		MailAttribute:        cfg.MailAttribute,
		DisplayNameAttribute: cfg.DisplayNameAttribute,
		TitleAttribute:       cfg.TitleAttribute,
		UserFilter:           cfg.UserFilter,
		SyncUserFilter:       cfg.SyncUserFilter,
	}
}
