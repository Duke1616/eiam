package ioc

import (
	"fmt"

	"github.com/Duke1616/ecmdb/pkg/cryptox"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/identity_source"
	"github.com/spf13/viper"
)

func InitIdentitySourceService(repo repository.IIdentitySourceRepository) identity_source.IService {
	type Config struct {
		EncryptionKey string `mapstructure:"encryption_key"`
	}
	var cfg Config
	err := viper.UnmarshalKey("identity", &cfg)
	if err != nil {
		panic(fmt.Errorf("unable to decode identity config: %v", err))
	}

	if cfg.EncryptionKey == "" {
		panic("identity encryption key is required")
	}

	// 直接引用 ecmdb 的加密管理器
	cm := cryptox.NewCryptoManager("v1").
		Register("v1", cryptox.MustNewAESCryptoV2(cfg.EncryptionKey))

	return identity_source.NewService(repo, cm)
}
