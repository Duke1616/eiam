package oidc

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"

	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/pkg/certx"
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

// NewClusterKeyManager 创建或从共享缓存加载 RSA 签名密钥管理器 (纯内存入参，文件 I/O 由 IoC 配置层统一收敛)
func NewClusterKeyManager(ctx context.Context, keyID, privateKeyPEM string, c cache.IOidcCache) (IKeyManager, error) {
	if keyID == "" {
		keyID = "eiam-default-key"
	}

	pemBytes := []byte(strings.TrimSpace(privateKeyPEM))

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
	return certx.GenerateRSAPEM(2048)
}

// parseOrGeneratePrivateKey 将 PEM 字节解析为 RSA 私钥；若为空则兜底自动生成
func parseOrGeneratePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	if len(pemBytes) == 0 {
		return certx.GenerateRSAKey(2048)
	}
	return certx.ParseKey(pemBytes)
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

	return certx.EncodeKeyPEM(km.privateKey), nil
}

func (km *keyManager) ExportPublicKeyPEM() (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	return certx.EncodePublicKeyPEM(km.publicKey)
}
