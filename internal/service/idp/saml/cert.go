package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/pkg/certx"
)

const defaultClusterCertKey = "eiam-default-saml-cert"

// ICertificateManager SAML 2.0 X.509 证书与 RSA 签名密钥管理器接口
type ICertificateManager interface {
	// Certificate 获取当前生效的 X.509 证书实例
	Certificate() *x509.Certificate
	// PrivateKey 获取用于 XML-DSig 签名的 RSA 私钥
	PrivateKey() *rsa.PrivateKey
	// CertificatePEM 导出 PKIX 格式的标准 PEM 证书文本 (包含 -----BEGIN CERTIFICATE-----)
	CertificatePEM() string
	// CertificateBase64DER 导出供 SAML Metadata <ds:X509Certificate> 使用的纯 Base64 DER 编码
	CertificateBase64DER() string
	// FingerprintSHA256 导出证书 SHA-256 指纹 (冒号分隔大写十六进制，如 AA:BB:CC...)
	FingerprintSHA256() string
	// Subject 导出证书的主题 CommonName 或 DN
	Subject() string
	// ValidityPeriod 导出证书生效与失效时间
	ValidityPeriod() (notBefore time.Time, notAfter time.Time)
	// Detail 导出当前生效的 X.509 证书元数据详情快照
	Detail() CertificateDetail
	// RotateCertificate 重新生成并轮换 X.509 证书与私钥 (同步覆盖 Redis 集群持久化数据)
	RotateCertificate(ctx context.Context, validityDays int) (*CertificateDetail, error)
}

// certSnapshot 封装原子状态快照，用于线程安全的高并发读取
type certSnapshot struct {
	cert        *x509.Certificate
	privKey     *rsa.PrivateKey
	certPEM     string
	base64DER   string
	fingerprint string
	subject     string
	notBefore   time.Time
	notAfter    time.Time
}

type certificateManager struct {
	mu           sync.RWMutex
	cache        cache.ISamlCache
	validityDays int
	state        certSnapshot
}

// NewClusterCertificateManager 构造具备分布式集群持久化感知能力的 SAML 证书管理器 (纯内存入参，文件 I/O 由 IoC 配置层统一收敛)
func NewClusterCertificateManager(ctx context.Context, certPEM, keyPEM string, validityDays int, c cache.ISamlCache) (ICertificateManager, error) {
	if validityDays <= 0 {
		validityDays = 1095 // 默认 3 年 (1095 天)
	}

	bundle, err := loadOrGenerateCredentials(ctx, certPEM, keyPEM, validityDays, c)
	if err != nil {
		return nil, err
	}

	mgr := &certificateManager{
		cache:        c,
		validityDays: validityDays,
	}
	mgr.updateState(bundle)
	return mgr, nil
}

// loadOrGenerateCredentials 遵循清晰的凭据加载流程：外部配置优先 > 集群缓存持久化
func loadOrGenerateCredentials(ctx context.Context, certPEM, keyPEM string, validityDays int, c cache.ISamlCache) (*certx.Certificate, error) {
	certTrimmed := strings.TrimSpace(certPEM)
	keyTrimmed := strings.TrimSpace(keyPEM)

	// 1. 若显式提供了静态证书与私钥 PEM 文本，直接内存加载
	if certTrimmed != "" || keyTrimmed != "" {
		if certTrimmed == "" || keyTrimmed == "" {
			return nil, errors.New("SAML 证书与私钥必须成对提供")
		}
		return certx.New(certTrimmed, keyTrimmed)
	}

	// 2. 从分布式集群共享缓存中获取，若首次启动则原子生成并持久化
	clusterCert, err := c.GetOrSetClusterCertificate(ctx, defaultClusterCertKey, func() (*cache.SamlClusterCertificate, error) {
		newBundle, genErr := certx.GenerateSelfSigned(certx.CertConfig{
			CommonName:   "EIAM SAML Identity Provider",
			Organization: "EIAM Enterprise",
			Validity:     time.Duration(validityDays) * 24 * time.Hour,
		})
		if genErr != nil {
			return nil, genErr
		}
		return &cache.SamlClusterCertificate{
			CertPEM: newBundle.CertPEM(),
			KeyPEM:  newBundle.KeyPEM(),
		}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("初始化集群 SAML 证书失败: %w", err)
	}

	return certx.New(clusterCert.CertPEM, clusterCert.KeyPEM)
}

// updateState 统一更新快照状态，消除构造函数与轮换函数的重复计算
func (m *certificateManager) updateState(bundle *certx.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = certSnapshot{
		cert:        bundle.X509,
		privKey:     bundle.Key,
		certPEM:     bundle.CertPEM(),
		base64DER:   bundle.Base64DER(),
		fingerprint: bundle.Fingerprint(),
		subject:     bundle.CommonName(),
		notBefore:   bundle.X509.NotBefore,
		notAfter:    bundle.X509.NotAfter,
	}
}

func (m *certificateManager) Certificate() *x509.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.cert
}

func (m *certificateManager) PrivateKey() *rsa.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.privKey
}

func (m *certificateManager) CertificatePEM() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.certPEM
}

func (m *certificateManager) CertificateBase64DER() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.base64DER
}

func (m *certificateManager) FingerprintSHA256() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.fingerprint
}

func (m *certificateManager) Subject() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.subject
}

func (m *certificateManager) ValidityPeriod() (time.Time, time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.notBefore, m.state.notAfter
}

func (m *certificateManager) Detail() CertificateDetail {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return CertificateDetail{
		PEM:         m.state.certPEM,
		Fingerprint: m.state.fingerprint,
		Subject:     m.state.subject,
		NotBefore:   m.state.notBefore.UTC().Format(time.RFC3339),
		NotAfter:    m.state.notAfter.UTC().Format(time.RFC3339),
	}
}

// RotateCertificate 重新生成并轮换 X.509 证书与私钥 (原子同步更新 Redis 集群持久化数据)
func (m *certificateManager) RotateCertificate(ctx context.Context, validityDays int) (*CertificateDetail, error) {
	if validityDays <= 0 {
		validityDays = m.validityDays
	}
	newBundle, err := certx.GenerateSelfSigned(certx.CertConfig{
		CommonName:   "EIAM SAML Identity Provider",
		Organization: "EIAM Enterprise",
		Validity:     time.Duration(validityDays) * 24 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("生成新 SAML 证书失败: %w", err)
	}

	// 同步持久化覆盖 Redis 集群缓存
	if err = m.cache.SetClusterCertificate(ctx, defaultClusterCertKey, &cache.SamlClusterCertificate{
		CertPEM: newBundle.CertPEM(),
		KeyPEM:  newBundle.KeyPEM(),
	}); err != nil {
		return nil, fmt.Errorf("同步更新集群证书持久化缓存失败: %w", err)
	}

	m.updateState(newBundle)
	detail := m.Detail()
	return &detail, nil
}
