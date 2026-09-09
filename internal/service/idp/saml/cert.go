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
	"github.com/samber/lo"
	"github.com/spf13/viper"
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
	RotateCertificate(ctx context.Context, validityYears int) (*CertificateDetail, error)
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
	mu    sync.RWMutex
	cache cache.ISamlCache
	state certSnapshot
}

// NewClusterCertificateManager 构造具备分布式集群持久化感知能力的 SAML 证书管理器
func NewClusterCertificateManager(ctx context.Context, certPEMOrPath, keyPEMOrPath string, c cache.ISamlCache) (ICertificateManager, error) {
	cert, key, err := loadOrGenerateCredentials(ctx, certPEMOrPath, keyPEMOrPath, c)
	if err != nil {
		return nil, err
	}

	mgr := &certificateManager{cache: c}
	mgr.updateState(cert, key)
	return mgr, nil
}

// loadOrGenerateCredentials 遵循清晰的凭据加载流程：外部配置优先 > 集群缓存持久化
func loadOrGenerateCredentials(ctx context.Context, certPEMOrPath, keyPEMOrPath string, c cache.ISamlCache) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBytes := resolvePEMOrFilePath(certPEMOrPath)
	keyBytes := resolvePEMOrFilePath(keyPEMOrPath)

	// 1. 优先使用外部配置好的静态证书与私钥
	if len(certBytes) > 0 && len(keyBytes) > 0 {
		return parseCredentials(certBytes, keyBytes)
	}

	// 2. 从分布式集群共享缓存中获取，若首次启动则原子生成并持久化
	clusterCert, err := c.GetOrSetClusterCertificate(ctx, defaultClusterCertKey, func() (*cache.SamlClusterCertificate, error) {
		newCert, newKey, genErr := generateSelfSignedCertificate(0)
		if genErr != nil {
			return nil, genErr
		}
		return &cache.SamlClusterCertificate{
			CertPEM: encodeCertPEM(newCert),
			KeyPEM:  encodeKeyPEM(newKey),
		}, nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("初始化集群 SAML 证书失败: %w", err)
	}

	return parseCredentials([]byte(clusterCert.CertPEM), []byte(clusterCert.KeyPEM))
}

// updateState 统一更新快照状态，消除构造函数与轮换函数的重复计算
func (m *certificateManager) updateState(cert *x509.Certificate, key *rsa.PrivateKey) {
	subject := cert.Subject.CommonName
	if subject == "" {
		subject = cert.Subject.String()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = certSnapshot{
		cert:        cert,
		privKey:     key,
		certPEM:     encodeCertPEM(cert),
		base64DER:   base64.StdEncoding.EncodeToString(cert.Raw),
		fingerprint: formatFingerprint(cert.Raw),
		subject:     subject,
		notBefore:   cert.NotBefore,
		notAfter:    cert.NotAfter,
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
func (m *certificateManager) RotateCertificate(ctx context.Context, validityYears int) (*CertificateDetail, error) {
	newCert, newKey, err := generateSelfSignedCertificate(validityYears)
	if err != nil {
		return nil, fmt.Errorf("生成新 SAML 证书失败: %w", err)
	}

	certPEM := encodeCertPEM(newCert)
	keyPEM := encodeKeyPEM(newKey)

	// 同步持久化覆盖 Redis 集群缓存
	if err = m.cache.SetClusterCertificate(ctx, defaultClusterCertKey, &cache.SamlClusterCertificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}); err != nil {
		return nil, fmt.Errorf("同步更新集群证书持久化缓存失败: %w", err)
	}

	m.updateState(newCert, newKey)
	detail := m.Detail()
	return &detail, nil
}

// --- 纯函数与 PEM 编解码助手 ---

func encodeCertPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

func encodeKeyPEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func formatFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.Join(lo.Map(sum[:], func(b byte, _ int) string {
		return fmt.Sprintf("%02X", b)
	}), ":")
}

func parseCredentials(certBytes, keyBytes []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	privKey, err := parsePrivateKey(keyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 SAML 私钥失败: %w", err)
	}
	cert, err := parseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 SAML X.509 证书失败: %w", err)
	}
	return cert, privKey, nil
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

func generateSelfSignedCertificate(validityYears int) (*x509.Certificate, *rsa.PrivateKey, error) {
	if validityYears <= 0 {
		validityYears = viper.GetInt("idp.saml.cert_validity_years")
	}
	if validityYears <= 0 {
		validityYears = 3
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:   "EIAM SAML Identity Provider",
			Organization: []string{"EIAM Enterprise"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
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
