package ioc

import (
	"context"
	"fmt"
	"strings"

	"github.com/Duke1616/eiam/internal/repository/cache"
	oidcsvc "github.com/Duke1616/eiam/internal/service/idp/oidc"
	samlsvc "github.com/Duke1616/eiam/internal/service/idp/saml"
	"github.com/Duke1616/eiam/pkg/certx"
	"github.com/samber/lo"
	"github.com/spf13/viper"
)

// IdPConfig 统一身份提供商全量强类型配置
type IdPConfig struct {
	LoginURL string     `mapstructure:"login_url"`
	OIDC     OIDCConfig `mapstructure:"oidc"`
	SAML     SAMLConfig `mapstructure:"saml"`
	CAS      CASConfig  `mapstructure:"cas"`
}

// OIDCConfig OIDC 协议核心配置
type OIDCConfig struct {
	IssuerURL  string `mapstructure:"issuer_url"`
	KeyID      string `mapstructure:"key_id"`
	PrivateKey string `mapstructure:"private_key"`
	ConsentURL string `mapstructure:"consent_url"`
	EnableSLO  bool   `mapstructure:"enable_slo"`
}

// SAMLConfig SAML 2.0 协议证书与签名配置
type SAMLConfig struct {
	Certificate  string `mapstructure:"certificate"`
	PrivateKey   string `mapstructure:"private_key"`
	ValidityDays int    `mapstructure:"validity_days"` // 证书有效天数，默认 1095 天 (3年)
}

// CASConfig CAS 协议配置
type CASConfig struct {
	TicketTTLMinutes int `mapstructure:"ticket_ttl_minutes"` // Service Ticket 有效时长 (分钟)，默认 5 分钟
}

// defaultIdPConfig 提供安全的默认值工厂
func defaultIdPConfig() IdPConfig {
	return IdPConfig{
		LoginURL: "/login",
		OIDC: OIDCConfig{
			KeyID:      "eiam-default-key",
			ConsentURL: "/consent",
			EnableSLO:  false,
		},
		SAML: SAMLConfig{
			ValidityDays: 1095, // 默认 3 年
		},
		CAS: CASConfig{
			TicketTTLMinutes: 5, // 默认 5 分钟
		},
	}
}

// InitIdPConfig 统一加载并反序列化 IdP 强类型配置 (消除弱类型 GetString，并优雅兼容历史配置)
func InitIdPConfig() IdPConfig {
	var cfg IdPConfig
	if viper.IsSet("idp") {
		_ = viper.UnmarshalKey("idp", &cfg)
	}

	// 1. 优先读取新格式或兼容旧格式；若皆未配置则赋予默认值
	if cfg.LoginURL == "" {
		cfg.LoginURL = lo.CoalesceOrEmpty(viper.GetString("idp.login_url"), "/login")
	}
	if cfg.OIDC.KeyID == "" {
		cfg.OIDC.KeyID = lo.CoalesceOrEmpty(viper.GetString("idp.key_id"), "eiam-default-key")
	}
	if cfg.OIDC.PrivateKey == "" {
		cfg.OIDC.PrivateKey = viper.GetString("idp.private_key_pem")
	}
	if cfg.OIDC.IssuerURL == "" {
		cfg.OIDC.IssuerURL = viper.GetString("idp.issuer_url")
	}
	if cfg.OIDC.ConsentURL == "" {
		cfg.OIDC.ConsentURL = lo.CoalesceOrEmpty(viper.GetString("idp.consent_url"), "/consent")
	}
	if !cfg.OIDC.EnableSLO && viper.IsSet("idp.enable_slo") {
		cfg.OIDC.EnableSLO = viper.GetBool("idp.enable_slo")
	}

	// SAML 私钥未指定时，优先回退复用 OIDC 签名私钥
	if cfg.SAML.PrivateKey == "" {
		cfg.SAML.PrivateKey = cfg.OIDC.PrivateKey
	}
	if cfg.SAML.ValidityDays <= 0 {
		if years := viper.GetInt("idp.saml.cert_validity_years"); years > 0 {
			cfg.SAML.ValidityDays = years * 365
		} else {
			cfg.SAML.ValidityDays = 1095
		}
	}
	if cfg.CAS.TicketTTLMinutes <= 0 {
		cfg.CAS.TicketTTLMinutes = 5
	}

	return cfg
}

// InitKeyManager 构造 RSA 签名密钥管理器 (在 IoC 配置装配阶段解析文件路径并加载为纯 PEM 文本，向内注入纯内存模型)
func InitKeyManager(cfg IdPConfig, oidcCache cache.IOidcCache) (oidcsvc.IKeyManager, error) {
	keyPEM, err := resolveSourcePEM(cfg.OIDC.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("加载 OIDC 签名私钥配置失败: %w", err)
	}
	return oidcsvc.NewClusterKeyManager(context.Background(), cfg.OIDC.KeyID, keyPEM, oidcCache)
}

// InitSamlCertManager 构造 SAML 2.0 X.509 证书与私钥管理器 (在配置装配阶段解析文件路径并提供纯 PEM 字符串)
func InitSamlCertManager(cfg IdPConfig, samlCache cache.ISamlCache) (samlsvc.ICertificateManager, error) {
	certPEM, err := resolveSourcePEM(cfg.SAML.Certificate)
	if err != nil {
		return nil, fmt.Errorf("加载 SAML 证书配置失败: %w", err)
	}
	keyPEM, err := resolveSourcePEM(cfg.SAML.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("加载 SAML 私钥配置失败: %w", err)
	}

	return samlsvc.NewClusterCertificateManager(
		context.Background(),
		certPEM,
		keyPEM,
		cfg.SAML.ValidityDays,
		samlCache,
	)
}

// resolveSourcePEM 统一在配置层探测并读取数据源 (支持文件路径与内联 PEM 字符串，消除业务 Service 的磁盘 I/O 耦合)
func resolveSourcePEM(source string) (string, error) {
	trimmed := strings.TrimSpace(source)
	if trimmed == "" {
		return "", nil
	}
	bytes, err := certx.ResolveSource(trimmed)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
