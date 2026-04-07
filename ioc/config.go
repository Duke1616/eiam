package ioc

import "github.com/spf13/viper"

// InitServiceConfig 统一管理全局服务 URN 标识
func InitServiceConfig() string {
	type Config struct {
		Name string `mapstructure:"name"`
	}
	var cfg Config
	if err := viper.UnmarshalKey("service", &cfg); err != nil {
		return "iam" // 默认降级
	}

	if cfg.Name == "" {
		return "iam"
	}
	return cfg.Name
}
