package ioc

import (
	"context"

	"github.com/Duke1616/eiam/internal/repository/cache"
	idpsvc "github.com/Duke1616/eiam/internal/service/idp"
	"github.com/spf13/viper"
)

// InitKeyManager 构造 RSA 签名密钥管理器 (支持多副本 Redis 集群原子共享与本地配置加载)
func InitKeyManager(oidcCache cache.IOidcCache) (idpsvc.IKeyManager, error) {
	keyID := viper.GetString("idp.key_id")
	if keyID == "" {
		keyID = "eiam-default-key"
	}
	privateKeyPEM := viper.GetString("idp.private_key_pem")
	return idpsvc.NewClusterKeyManager(context.Background(), keyID, privateKeyPEM, oidcCache)
}
