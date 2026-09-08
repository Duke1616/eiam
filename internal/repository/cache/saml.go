package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

const (
	samlClusterCertPrefix = "eiam:idp:saml:cluster_cert:"
	samlClusterCertLock   = "eiam:idp:saml:lock:cluster_cert:"
)

// SamlClusterCertificate 集群共享的 SAML X.509 证书与 RSA 私钥 PEM 数据
type SamlClusterCertificate struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// ISamlCache SAML 协议缓存接口 (提供分布式多副本私钥与自签证书原子持久化)
type ISamlCache interface {
	// GetOrSetClusterCertificate 原子获取或持久化生成集群共享的 SAML 证书与私钥
	GetOrSetClusterCertificate(ctx context.Context, certID string, generateFn func() (*SamlClusterCertificate, error)) (*SamlClusterCertificate, error)
	// SetClusterCertificate 覆写持久化保存集群共享的 SAML 证书与私钥 (用于证书轮换与续期)
	SetClusterCertificate(ctx context.Context, certID string, cert *SamlClusterCertificate) error
}

type samlCache struct {
	cmd redis.Cmdable
}

// NewSamlCache 构造 SAML 缓存实例
func NewSamlCache(cmd redis.Cmdable) ISamlCache {
	return &samlCache{cmd: cmd}
}

// SetClusterCertificate 覆写持久化保存集群共享的 SAML 证书与私钥
func (c *samlCache) SetClusterCertificate(ctx context.Context, certID string, cert *SamlClusterCertificate) error {
	key := samlClusterCertPrefix + certID
	payload, err := json.Marshal(cert)
	if err != nil {
		return fmt.Errorf("序列化 SAML 证书数据失败: %w", err)
	}
	return c.cmd.Set(ctx, key, payload, 0).Err()
}

// GetOrSetClusterCertificate 基于 Redis 缓存实现集群自签证书的分布式安全持久化
func (c *samlCache) GetOrSetClusterCertificate(ctx context.Context, certID string, generateFn func() (*SamlClusterCertificate, error)) (*SamlClusterCertificate, error) {
	key := samlClusterCertPrefix + certID
	val, err := c.cmd.Get(ctx, key).Result()
	if err == nil && val != "" {
		var cert SamlClusterCertificate
		if unmarshalErr := json.Unmarshal([]byte(val), &cert); unmarshalErr == nil {
			return &cert, nil
		}
	}
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	// 缓存未命中：调用生成函数
	certData, genErr := generateFn()
	if genErr != nil {
		return nil, genErr
	}

	payload, err := json.Marshal(certData)
	if err != nil {
		return nil, fmt.Errorf("序列化 SAML 证书数据失败: %w", err)
	}

	// 利用 SETNX 保证多 Pod 并发冷启动时只有单个 Pod 生成并持久化
	ok, setErr := c.cmd.SetNX(ctx, key, payload, 0).Result()
	if setErr != nil {
		return nil, setErr
	}
	if !ok {
		// 并发竞争由其他 Pod 写入成功，重新读取权威数据
		reVal, reErr := c.cmd.Get(ctx, key).Result()
		if reErr != nil {
			return nil, reErr
		}
		var cert SamlClusterCertificate
		if unmarshalErr := json.Unmarshal([]byte(reVal), &cert); unmarshalErr != nil {
			return nil, unmarshalErr
		}
		return &cert, nil
	}

	return certData, nil
}
