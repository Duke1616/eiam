package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/spf13/viper"
)

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
	// RotateCertificate 重新生成并轮换 X.509 证书与私钥 (同步覆盖 Redis 集群持久化数据)
	RotateCertificate(ctx context.Context, validityYears int) (*CertificateDetail, error)
}

type certificateManager struct {
	mu          sync.RWMutex
	cache       cache.ISamlCache
	cert        *x509.Certificate
	privKey     *rsa.PrivateKey
	certPEM     string
	base64DER   string
	fingerprint string
	subject     string
	notBefore   time.Time
	notAfter    time.Time
}

// NewCertificateManager 构造本地独立 SAML 证书管理器 (未接入集群缓存时使用)
func NewCertificateManager(certPEMOrPath, keyPEMOrPath string) (ICertificateManager, error) {
	return NewClusterCertificateManager(context.Background(), certPEMOrPath, keyPEMOrPath, nil)
}

// NewClusterCertificateManager 构造具备分布式集群持久化感知能力的 SAML 证书管理器
// 1. 若配置中显式指定了证书与私钥 (路径或 PEM)，优先直接加载；
// 2. 若未配置，且集群缓存可用，原子检查或生成证书并永久保存在 Redis 中，确保多 Pod 实例与发版重启完全一致；
// 3. 若缓存不可用，降级为本地内存生成自签名证书。
func NewClusterCertificateManager(ctx context.Context, certPEMOrPath, keyPEMOrPath string, c cache.ISamlCache) (ICertificateManager, error) {
	certBytes := resolvePEMOrFilePath(certPEMOrPath)
	keyBytes := resolvePEMOrFilePath(keyPEMOrPath)

	var (
		cert    *x509.Certificate
		privKey *rsa.PrivateKey
		err     error
	)

	// 1. 若未同时提供证书与私钥，尝试从分布式集群共享持久化缓存中读取或原子生成
	if (len(certBytes) == 0 || len(keyBytes) == 0) && c != nil {
		clusterCert, cacheErr := c.GetOrSetClusterCertificate(ctx, "eiam-default-saml-cert", func() (*cache.SamlClusterCertificate, error) {
			newCert, newKey, genErr := generateSelfSignedCertificate(0)
			if genErr != nil {
				return nil, genErr
			}
			certPEM := string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: newCert.Raw,
			}))
			keyPEM := string(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(newKey),
			}))
			return &cache.SamlClusterCertificate{
				CertPEM: certPEM,
				KeyPEM:  keyPEM,
			}, nil
		})
		if cacheErr == nil && clusterCert != nil {
			certBytes = []byte(clusterCert.CertPEM)
			keyBytes = []byte(clusterCert.KeyPEM)
		}
	}

	// 2. 若仍未获取到有效凭据，降级本地内存自签生成
	if len(certBytes) == 0 || len(keyBytes) == 0 {
		cert, privKey, err = generateSelfSignedCertificate(0)
		if err != nil {
			return nil, fmt.Errorf("自动生成自签名 SAML 证书失败: %w", err)
		}
	} else {
		privKey, err = parsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("解析 SAML 私钥失败: %w", err)
		}

		cert, err = parseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("解析 SAML X.509 证书失败: %w", err)
		}
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	subject := cert.Subject.CommonName
	if subject == "" {
		subject = cert.Subject.String()
	}

	return &certificateManager{
		cache:       c,
		cert:        cert,
		privKey:     privKey,
		certPEM:     string(pemBlock),
		base64DER:   base64.StdEncoding.EncodeToString(cert.Raw),
		fingerprint: formatFingerprint(cert.Raw),
		subject:     subject,
		notBefore:   cert.NotBefore,
		notAfter:    cert.NotAfter,
	}, nil
}

func (m *certificateManager) Certificate() *x509.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert
}

func (m *certificateManager) PrivateKey() *rsa.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.privKey
}

func (m *certificateManager) CertificatePEM() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.certPEM
}

func (m *certificateManager) CertificateBase64DER() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.base64DER
}

func (m *certificateManager) FingerprintSHA256() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fingerprint
}

func (m *certificateManager) Subject() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.subject
}

func (m *certificateManager) ValidityPeriod() (time.Time, time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.notBefore, m.notAfter
}

func formatFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// resolvePEMOrFilePath 辅助函数：如果是本地文件路径则读取文件，否则直接按 PEM 字符串处理
func resolvePEMOrFilePath(input string) []byte {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	if !strings.Contains(input, "-----BEGIN") {
		if content, err := os.ReadFile(input); err == nil {
			return content
		}
	}
	return []byte(input)
}

func parsePrivateKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("私钥 PEM 解码失败")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}
	return nil, errors.New("不支持的私钥格式，仅支持 PKCS1/PKCS8 RSA 私钥")
}

func parseCertificate(certBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, errors.New("X.509 证书 PEM 解码失败")
	}
	return x509.ParseCertificate(block.Bytes)
}

// RotateCertificate 重新生成并轮换 X.509 证书与私钥 (原子同步更新 Redis 集群持久化数据)
func (m *certificateManager) RotateCertificate(ctx context.Context, validityYears int) (*CertificateDetail, error) {
	newCert, newKey, err := generateSelfSignedCertificate(validityYears)
	if err != nil {
		return nil, fmt.Errorf("生成新 SAML 证书失败: %w", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCert.Raw,
	})
	keyBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(newKey),
	})

	certPEM := string(pemBlock)
	keyPEM := string(keyBlock)

	// 若接入了集群缓存，同步持久化覆盖 Redis
	if m.cache != nil {
		err = m.cache.SetClusterCertificate(ctx, "eiam-default-saml-cert", &cache.SamlClusterCertificate{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		})
		if err != nil {
			return nil, fmt.Errorf("同步更新集群证书持久化缓存失败: %w", err)
		}
	}

	subject := newCert.Subject.CommonName
	if subject == "" {
		subject = newCert.Subject.String()
	}

	m.mu.Lock()
	m.cert = newCert
	m.privKey = newKey
	m.certPEM = certPEM
	m.base64DER = base64.StdEncoding.EncodeToString(newCert.Raw)
	m.fingerprint = formatFingerprint(newCert.Raw)
	m.subject = subject
	m.notBefore = newCert.NotBefore
	m.notAfter = newCert.NotAfter
	m.mu.Unlock()

	return &CertificateDetail{
		PEM:         certPEM,
		Fingerprint: m.fingerprint,
		Subject:     subject,
		NotBefore:   newCert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:    newCert.NotAfter.UTC().Format(time.RFC3339),
	}, nil
}

// generateSelfSignedCertificate 自动生成高强度 RSA 2048 位的自签名 X.509 证书
func generateSelfSignedCertificate(validityYears int) (*x509.Certificate, *rsa.PrivateKey, error) {
	if validityYears <= 0 {
		validityYears = viper.GetInt("idp.saml.cert_validity_years")
	}
	if validityYears <= 0 {
		validityYears = 3 // 默认 3 年
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "EIAM SAML Identity Provider",
			Organization: []string{"EIAM Enterprise"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute), // 防客户端时钟微小偏差
		NotAfter:              time.Now().AddDate(validityYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}
