package certx

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// PrivateKey 约束支持的强类型私钥指针类型
type PrivateKey interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
}

// PublicKey 约束支持的强类型公钥指针类型
type PublicKey interface {
	*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

// GenerateRSAKey 生成指定位数的 RSA 秘钥对，若 bits <= 0 则默认生成 2048 位
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits <= 0 {
		bits = 2048
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// GenerateRSAPEM 生成指定位数的 RSA 私钥并直接输出 PKCS1 PEM 字符串
func GenerateRSAPEM(bits int) (string, error) {
	priv, err := GenerateRSAKey(bits)
	if err != nil {
		return "", fmt.Errorf("生成 RSA 秘钥失败: %w", err)
	}
	return EncodeKeyPEM(priv), nil
}

// EncodeKeyPEM 将 RSA 私钥编码为 PKCS1 标准 PEM 字符串
func EncodeKeyPEM(key *rsa.PrivateKey) string {
	if key == nil {
		return ""
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(block))
}

// EncodePublicKeyPEM 将 RSA 公钥导出为标准 PKIX PEM 字符串
func EncodePublicKeyPEM(pub *rsa.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("公钥指针不能为空")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("导出 PKIX 公钥失败: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// ParseKeyAs 利用泛型解析私钥，并自动安全转换为指定的目标强类型
func ParseKeyAs[T PrivateKey, S Source](source S) (T, error) {
	var zero T
	rawBytes, err := ResolveSource(source)
	if err != nil {
		return zero, err
	}

	block, _ := pem.Decode(rawBytes)
	if block == nil {
		return zero, errors.New("私钥 PEM 解码失败: 无效的 PEM 格式")
	}

	// 1. 优先尝试解析 PKCS1 RSA 私钥
	if rsaKey, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes); pkcs1Err == nil {
		if val, ok := any(rsaKey).(T); ok {
			return val, nil
		}
	}

	// 2. 兼容解析 PKCS8 私钥
	k, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if pkcs8Err == nil {
		if val, ok := k.(T); ok {
			return val, nil
		}
		return zero, fmt.Errorf("私钥类型不匹配: 期望目标类型 %T, 实际解析得到 %T", zero, k)
	}

	return zero, fmt.Errorf("解析私钥失败 (PKCS1/PKCS8 均不匹配): %w", pkcs8Err)
}

// ParseKey 解析 RSA 私钥的强类型快捷函数
func ParseKey[S Source](source S) (*rsa.PrivateKey, error) {
	return ParseKeyAs[*rsa.PrivateKey](source)
}

// ParsePublicKey 解析标准 PKIX PEM 格式的 RSA 公钥
func ParsePublicKey[S Source](source S) (*rsa.PublicKey, error) {
	rawBytes, err := ResolveSource(source)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(rawBytes)
	if block == nil {
		return nil, errors.New("公钥 PEM 解码失败: 无效的 PEM 格式")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 PKIX 公钥失败: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥非 RSA 格式: 实际为 %T", pub)
	}

	return rsaPub, nil
}
