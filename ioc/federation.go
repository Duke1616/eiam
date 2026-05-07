package ioc

import (
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/service/identity_source"
	"github.com/Duke1616/eiam/internal/service/user/ldap"
)

// InitCredentialProviders 显式返回系统支持的所有凭证身份源列表
func InitCredentialProviders(idsSvc identity_source.IService) []domain.CredentialProvider {
	return []domain.CredentialProvider{
		ldap.NewDynamicLdapProvider(idsSvc),
	}
}
