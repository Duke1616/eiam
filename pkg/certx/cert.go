package certx

import (
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
	"strings"
	"time"

	"github.com/samber/lo"
)

// Certificate 统一封装 X.509 证书与配套私钥，提供内聚、流畅的格式导出与取值方法
type Certificate struct {
	X509 *x509.Certificate
	Key  *rsa.PrivateKey
}

// CertPEM 导出标准 PEM 证书格式文本 (包含 -----BEGIN CERTIFICATE-----)
func (c *Certificate) CertPEM() string {
	if c.X509 == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.X509.Raw,
	}))
}

// KeyPEM 导出配套 RSA 私钥的 PKCS1 PEM 文本
func (c *Certificate) KeyPEM() string {
	return EncodeKeyPEM(c.Key)
}

// CombinedPEM 导出合并了证书与私钥的单份完整 PEM 文本 (常用于 fullchain 或本地集群挂载)
func (c *Certificate) CombinedPEM() string {
	return c.CertPEM() + "\n" + c.KeyPEM()
}

// Base64DER 导出 SAML Metadata <ds:X509Certificate> 专用的纯 Base64 DER 编码
func (c *Certificate) Base64DER() string {
	if c.X509 == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(c.X509.Raw)
}

// Fingerprint 计算证书 SHA-256 指纹 (冒号分隔大写十六进制，如 AA:BB:CC...)
func (c *Certificate) Fingerprint() string {
	if c.X509 == nil {
		return ""
	}
	return FingerprintSHA256(c.X509.Raw)
}

// CommonName 获取证书主体 CommonName，若为空则退化返回完整 Subject 字符串
func (c *Certificate) CommonName() string {
	if c.X509 == nil {
		return ""
	}
	if cn := c.X509.Subject.CommonName; cn != "" {
		return cn
	}
	return c.X509.Subject.String()
}

// CertConfig 证书生成配置
type CertConfig struct {
	CommonName    string
	Organization  string
	Validity      time.Duration
	ValidityYears int
	KeyBits       int
}

// New 从证书与私钥数据源（文件路径、PEM 文本或原始字节）直接解析并装配 Certificate 对象
func New[S Source](certSource, keySource S) (*Certificate, error) {
	cert, err := ParseCert(certSource)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	key, err := ParseKey(keySource)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}

	return &Certificate{
		X509: cert,
		Key:  key,
	}, nil
}

// GenerateSelfSigned 零配置或按需生成自签名 X.509 证书与配套私钥，直接返回装配好的 Certificate 对象
func GenerateSelfSigned(cfg CertConfig) (*Certificate, error) {
	if cfg.CommonName == "" {
		cfg.CommonName = "EIAM SAML Identity Provider"
	}
	if cfg.Organization == "" {
		cfg.Organization = "EIAM Enterprise"
	}
	if cfg.KeyBits <= 0 {
		cfg.KeyBits = 2048
	}

	priv, err := GenerateRSAKey(cfg.KeyBits)
	if err != nil {
		return nil, fmt.Errorf("生成 RSA 秘钥对失败: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("生成证书序列号失败: %w", err)
	}

	notBefore := time.Now().Add(-10 * time.Minute)
	var notAfter time.Time
	if cfg.Validity > 0 {
		notAfter = notBefore.Add(cfg.Validity)
	} else {
		if cfg.ValidityYears <= 0 {
			cfg.ValidityYears = 3
		}
		notAfter = time.Now().AddDate(cfg.ValidityYears, 0, 0)
	}

	template := x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: []string{cfg.Organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("自签 X.509 证书失败: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("解析自签证书 DER 失败: %w", err)
	}

	return &Certificate{
		X509: cert,
		Key:  priv,
	}, nil
}

// ParseCert 解析任意数据源（路径、PEM 或字节）的单个 X.509 证书
func ParseCert[S Source](source S) (*x509.Certificate, error) {
	rawBytes, err := ResolveSource(source)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(rawBytes)
	if block == nil {
		if cert, derErr := x509.ParseCertificate(rawBytes); derErr == nil {
			return cert, nil
		}
		return nil, errors.New("X.509 证书解析失败: 既非有效 PEM 格式，亦非有效 DER 二进制")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 X.509 证书 DER 失败: %w", err)
	}

	return cert, nil
}

// FingerprintSHA256 计算证书原始 DER 字节的 SHA-256 指纹
func FingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.Join(lo.Map(sum[:], func(b byte, _ int) string {
		return fmt.Sprintf("%02X", b)
	}), ":")
}
