package ioc

import (
	"github.com/Duke1616/eiam/internal/pkg/middleware"
	"github.com/spf13/viper"
)

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

// InitAuditConfig 加载安全审计中间件配置
func InitAuditConfig() middleware.AuditConfig {
	cfg := middleware.DefaultAuditConfig()
	if viper.IsSet("audit") {
		_ = viper.UnmarshalKey("audit", &cfg)
	}
	return cfg
}

// InitAuditMatcher 构建审计规则匹配器
func InitAuditMatcher(cfg middleware.AuditConfig) middleware.IAuditMatcher {
	return middleware.NewAuditMatcher(cfg)
}
