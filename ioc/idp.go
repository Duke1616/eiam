package ioc

import (
	"context"

	"github.com/Duke1616/eiam/internal/repository/cache"
	oidcsvc "github.com/Duke1616/eiam/internal/service/idp/oidc"
	samlsvc "github.com/Duke1616/eiam/internal/service/idp/saml"
	"github.com/spf13/viper"
)

// InitKeyManager 构造 RSA 签名密钥管理器 (支持多副本 Redis 集群原子共享与本地配置加载)
func InitKeyManager(oidcCache cache.IOidcCache) (oidcsvc.IKeyManager, error) {
	keyID := viper.GetString("idp.key_id")
	if keyID == "" {
		keyID = "eiam-default-key"
	}
	privateKeyPEM := viper.GetString("idp.private_key_pem")
	return oidcsvc.NewClusterKeyManager(context.Background(), keyID, privateKeyPEM, oidcCache)
}

// InitSamlCertManager 构造 SAML 2.0 X.509 证书与私钥管理器 (支持多副本 Redis 集群原子持久化与本地配置加载)
func InitSamlCertManager(samlCache cache.ISamlCache) (samlsvc.ICertificateManager, error) {
	certPEM := viper.GetString("idp.saml.certificate")
	keyPEM := viper.GetString("idp.saml.private_key")
	if keyPEM == "" {
		keyPEM = viper.GetString("idp.private_key_pem")
	}
	return samlsvc.NewClusterCertificateManager(context.Background(), certPEM, keyPEM, samlCache)
}
