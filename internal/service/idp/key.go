package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// IKeyManager RSA 签名密钥管理器接口
type IKeyManager interface {
	// KeyID 获取当前签名密钥的唯一标识符
	KeyID() string
	// PublicKeySet 导出包含当前公钥的 JWKS 集合
	PublicKeySet() jose.JSONWebKeySet
	// KeyByID 根据 KeyID 查找匹配的 JWK 公钥
	KeyByID(keyID string) (*jose.JSONWebKey, error)
	// SignJWT 使用当前私钥签发 RS256 格式的 JWT
	SignJWT(claims jwt.Claims) (string, error)
	// VerifyJWT 使用公钥校验 JWT 签名并解析 Claims
	VerifyJWT(tokenString string, claims jwt.Claims) (*jwt.Token, error)
	// ExportPrivateKeyPEM 导出 PKCS1 格式的私钥 PEM 字符串
	ExportPrivateKeyPEM() (string, error)
	// ExportPublicKeyPEM 导出 PKIX 格式的公钥 PEM 字符串
	ExportPublicKeyPEM() (string, error)
}

type keyManager struct {
	mu         sync.RWMutex
	keyID      string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewKeyManager 创建或加载 RSA 签名密钥管理器
func NewKeyManager(keyID, privateKeyPEMOrPath string) (IKeyManager, error) {
	return NewClusterKeyManager(context.Background(), keyID, privateKeyPEMOrPath, nil)
}

// NewClusterKeyManager 创建或从共享缓存加载 RSA 签名密钥管理器
func NewClusterKeyManager(ctx context.Context, keyID, privateKeyPEMOrPath string, c cache.IOidcCache) (IKeyManager, error) {
	if keyID == "" {
		keyID = "eiam-default-key"
	}

	pemBytes := []byte(privateKeyPEMOrPath)

	// 检查是否为磁盘文件路径
	if len(pemBytes) > 0 && !strings.Contains(privateKeyPEMOrPath, "-----BEGIN") {
		if content, readErr := os.ReadFile(privateKeyPEMOrPath); readErr == nil {
			pemBytes = content
		}
	}

	// 若未显式配置私钥，尝试从集群共享缓存中原子拉取或生成
	// 集群模式下必须共享同一把签名密钥，否则不同 Pod 签发的 Token 无法互相验签
	if len(pemBytes) == 0 && c != nil {
		if clusterPEM, err := c.GetOrSetClusterSigningKey(ctx, keyID, generateRSAPEMString); err == nil {
			pemBytes = []byte(clusterPEM)
		}
	}

	priv, err := parseOrGeneratePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	return &keyManager{
		keyID:      keyID,
		privateKey: priv,
		publicKey:  &priv.PublicKey,
	}, nil
}

// generateRSAPEMString 生成 RSA-2048 私钥并编码为 PKCS1 PEM 字符串
// 此函数作为回调传入 GetOrSetClusterSigningKey，确保集群内只有一个 Pod 负责生成密钥并写入缓存
func generateRSAPEMString() (string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("生成 RSA 秘钥对失败: %w", err)
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	return string(pem.EncodeToMemory(block)), nil
}

// parseOrGeneratePrivateKey 将 PEM 字节解析为 RSA 私钥；若为空则兜底自动生成
func parseOrGeneratePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	if len(pemBytes) == 0 {
		// 兜底生成高强度 2048 位秘钥对
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("生成 RSA 秘钥对失败: %w", err)
		}
		return priv, nil
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("解析 RSA 私钥 PEM 格式失败")
	}

	// 优先以 PKCS1 格式解析
	if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return priv, nil
	}

	// 降级兼容 PKCS8 格式
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 RSA 私钥失败 (PKCS1/PKCS8 均不匹配): %w", err)
	}

	priv, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("传入的私钥非 RSA 格式")
	}
	return priv, nil
}

func (km *keyManager) KeyID() string {
	return km.keyID
}

func (km *keyManager) PublicKeySet() jose.JSONWebKeySet {
	km.mu.RLock()
	defer km.mu.RUnlock()

	jwk := jose.JSONWebKey{
		Key:       km.publicKey,
		KeyID:     km.keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}
}

func (km *keyManager) KeyByID(keyID string) (*jose.JSONWebKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if keyID != "" && keyID != km.keyID {
		return nil, fmt.Errorf("未找到对应 KeyID 的公钥: %s", keyID)
	}

	jwk := &jose.JSONWebKey{
		Key:       km.publicKey,
		KeyID:     km.keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	return jwk, nil
}

// SignJWT 使用 RS256 算法与本地 RSA 私钥签发 JWT
func (km *keyManager) SignJWT(claims jwt.Claims) (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = km.keyID
	return token.SignedString(km.privateKey)
}

// VerifyJWT 使用 RSA 公钥解析与校验 JWT
func (km *keyManager) VerifyJWT(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	return jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("非法的签名算法: %v", token.Header["alg"])
		}
		return km.publicKey, nil
	})
}

func (km *keyManager) ExportPrivateKeyPEM() (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	der := x509.MarshalPKCS1PrivateKey(km.privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func (km *keyManager) ExportPublicKeyPEM() (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	der, err := x509.MarshalPKIXPublicKey(km.publicKey)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
}
