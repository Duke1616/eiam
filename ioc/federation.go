package ioc

import (
	"fmt"

	"github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/internal/service/user/ldapx"
	"github.com/spf13/viper"
)

func InitLdapConfig() ldapx.Config {
	var cfg ldapx.Config
	if err := viper.UnmarshalKey("ldap", &cfg); err != nil {
		panic(fmt.Errorf("unable to decode into structure: %v", err))
	}
	return cfg
}

// InitIdentityProviders 显式返回系统支持的所有联邦身份源列表
// 这次我们一次性解决 Wire 注入 []IdentityProvider 的问题
func InitIdentityProviders(lconf ldapx.Config) []user.IdentityProvider {
	return []user.IdentityProvider{
		ldapx.NewLdap(lconf),
		// 未来您可以在这里直接追加: feishu.NewProvider(fconf),
	}
}
