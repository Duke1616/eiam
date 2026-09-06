package idp

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inMemoryOidcCache 用于单测模拟 Redis 集群共享存储
type inMemoryOidcCache struct {
	mu   sync.Mutex
	data map[string]string
}

func newInMemoryOidcCache() *inMemoryOidcCache {
	return &inMemoryOidcCache{
		data: make(map[string]string),
	}
}

func (c *inMemoryOidcCache) GetOrSetClusterSigningKey(ctx context.Context, keyID string, generateFn func() (string, error)) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if val, ok := c.data[keyID]; ok && val != "" {
		return val, nil
	}

	pemStr, err := generateFn()
	if err != nil {
		return "", err
	}
	c.data[keyID] = pemStr
	return pemStr, nil
}

func (c *inMemoryOidcCache) SaveAuthCodeContext(ctx context.Context, code string, data []byte) error { return nil }
func (c *inMemoryOidcCache) GetAndDelAuthCodeContext(ctx context.Context, code string) ([]byte, error) { return nil, nil }
func (c *inMemoryOidcCache) SaveConsentContext(ctx context.Context, consentID string, data []byte) error { return nil }
func (c *inMemoryOidcCache) GetConsentContext(ctx context.Context, consentID string) ([]byte, error) { return nil, nil }
func (c *inMemoryOidcCache) GetAndDelConsentContext(ctx context.Context, consentID string) ([]byte, error) { return nil, nil }
func (c *inMemoryOidcCache) SaveRefreshToken(ctx context.Context, token string, data []byte) error { return nil }
func (c *inMemoryOidcCache) GetRefreshToken(ctx context.Context, token string) ([]byte, error) { return nil, nil }
func (c *inMemoryOidcCache) DeleteRefreshToken(ctx context.Context, token string) error        { return nil }
func (c *inMemoryOidcCache) RevokeToken(ctx context.Context, token string, ttl time.Duration) error { return nil }
func (c *inMemoryOidcCache) IsTokenRevoked(ctx context.Context, token string) (bool, error)   { return false, nil }
func (c *inMemoryOidcCache) TrackUserRefreshToken(ctx context.Context, userID, token string) error { return nil }
func (c *inMemoryOidcCache) DeleteUserRefreshTokens(ctx context.Context, userID string) error  { return nil }
func (c *inMemoryOidcCache) SaveOAuthClient(ctx context.Context, clientID string, data []byte) error { return nil }
func (c *inMemoryOidcCache) GetOAuthClient(ctx context.Context, clientID string) ([]byte, error) { return nil, nil }
func (c *inMemoryOidcCache) DeleteOAuthClient(ctx context.Context, clientID string) error      { return nil }
func (c *inMemoryOidcCache) Ping(ctx context.Context) error                                   { return nil }

func TestClusterKeyManager_MultiPodConsistency(t *testing.T) {
	sharedCache := newInMemoryOidcCache()

	// 模拟 Pod 1 启动
	km1, err := NewClusterKeyManager(context.Background(), "cluster-test-key", "", sharedCache)
	require.NoError(t, err)
	require.NotNil(t, km1)

	pubPEM1, err := km1.ExportPublicKeyPEM()
	require.NoError(t, err)
	privPEM1, err := km1.ExportPrivateKeyPEM()
	require.NoError(t, err)

	// 模拟 Pod 2 启动 (连接同一个 Redis 集群)
	km2, err := NewClusterKeyManager(context.Background(), "cluster-test-key", "", sharedCache)
	require.NoError(t, err)
	require.NotNil(t, km2)

	pubPEM2, err := km2.ExportPublicKeyPEM()
	require.NoError(t, err)
	privPEM2, err := km2.ExportPrivateKeyPEM()
	require.NoError(t, err)

	// 断言多副本 Pod 间的密钥与 JWKS 导出完全一致
	assert.Equal(t, privPEM1, privPEM2, "多副本导出的 RSA 私钥必须完全一致")
	assert.Equal(t, pubPEM1, pubPEM2, "多副本导出的 RSA 公钥必须完全一致")
	assert.Equal(t, km1.PublicKeySet(), km2.PublicKeySet(), "多副本对外暴露的 JWKS 必须完全一致")
	assert.Equal(t, km1.KeyID(), km2.KeyID(), "多副本 KeyID 必须一致")
}
