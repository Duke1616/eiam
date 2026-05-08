package ioc

import (
	"fmt"

	"github.com/Duke1616/ecmdb/pkg/cryptox"
	"github.com/spf13/viper"
)

func InitCryptoManager() *cryptox.CryptoManager {
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

	return cryptox.NewCryptoManager("v1").
		Register("v1", cryptox.MustNewAESCryptoV2(cfg.EncryptionKey))
}
