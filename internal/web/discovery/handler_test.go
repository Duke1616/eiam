package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDiscoveryService struct {
	syncCount int
	lastHash  string
}

func (m *mockDiscoveryService) Sync(ctx context.Context, req capability.SyncRequest) (bool, error) {
	currentHash := req.Hash()
	if m.lastHash != "" && m.lastHash == currentHash {
		return false, nil
	}
	m.syncCount++
	m.lastHash = currentHash
	return true, nil
}

type mockTenantKeyService struct {
	tokens map[string]string // token -> serviceName
}

func (m *mockTenantKeyService) GenerateKey(ctx context.Context, tenantID int64, description string) (domain.TenantKey, error) {
	return domain.TenantKey{}, nil
}
func (m *mockTenantKeyService) GetTenantIDByAccessKey(ctx context.Context, ak string) (int64, error) {
	return 0, nil
}
func (m *mockTenantKeyService) VerifyKey(ctx context.Context, ak, sk string) (int64, error) {
	return 0, nil
}
func (m *mockTenantKeyService) ListKeysByTenantID(ctx context.Context, tenantID int64) ([]domain.TenantKey, error) {
	return nil, nil
}
func (m *mockTenantKeyService) UpdateKeyStatus(ctx context.Context, id int64, status int) error {
	return nil
}
func (m *mockTenantKeyService) GenerateDiscoveryToken(ctx context.Context, serviceName string) (string, error) {
	tok := "eiam_sct_test_" + serviceName
	m.tokens[tok] = serviceName
	return tok, nil
}
func (m *mockTenantKeyService) VerifyDiscoveryToken(ctx context.Context, token string) (string, error) {
	svc, ok := m.tokens[token]
	if !ok {
		return "", errors.New("invalid token")
	}
	return svc, nil
}

func TestDiscoveryHandler_AuthAndHashCache(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("未开启认证 (默认): 无 Token 也可一键拉起放行", func(t *testing.T) {
		viper.Set("discovery.auth_enabled", false)

		mockSvc := &mockDiscoveryService{}
		mockTk := &mockTenantKeyService{tokens: make(map[string]string)}
		hdl := NewHandler(mockSvc, mockTk)

		engine := gin.New()
		hdl.PublicRoutes(engine)

		reqBody, _ := json.Marshal(capability.SyncRequest{Service: "ecmdb"})
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/discovery/sync", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 1, mockSvc.syncCount)
	})

	t.Run("开启认证后，无 Token 请求应被 401 拦截", func(t *testing.T) {
		viper.Set("discovery.auth_enabled", true)
		defer viper.Set("discovery.auth_enabled", false)

		mockSvc := &mockDiscoveryService{}
		mockTk := &mockTenantKeyService{tokens: make(map[string]string)}
		hdl := NewHandler(mockSvc, mockTk)

		engine := gin.New()
		hdl.PublicRoutes(engine)

		reqBody, _ := json.Marshal(capability.SyncRequest{Service: "order-service"})
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/discovery/sync", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, 0, mockSvc.syncCount)
	})

	t.Run("开启认证后，合法专属 Token 成功同步", func(t *testing.T) {
		viper.Set("discovery.auth_enabled", true)
		defer viper.Set("discovery.auth_enabled", false)

		mockSvc := &mockDiscoveryService{}
		mockTk := &mockTenantKeyService{tokens: map[string]string{
			"eiam_sct_ecmdb_valid": "ecmdb",
		}}
		hdl := NewHandler(mockSvc, mockTk)

		engine := gin.New()
		hdl.PublicRoutes(engine)

		reqBody, _ := json.Marshal(capability.SyncRequest{Service: "ecmdb"})
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/discovery/sync", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer eiam_sct_ecmdb_valid")

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 1, mockSvc.syncCount)
		assert.Contains(t, w.Body.String(), "资产同步指令已接收")
	})

	t.Run("开启认证后，Token 绑定的服务与上报服务不匹配被拦截 (防越权)", func(t *testing.T) {
		viper.Set("discovery.auth_enabled", true)
		defer viper.Set("discovery.auth_enabled", false)

		mockSvc := &mockDiscoveryService{}
		mockTk := &mockTenantKeyService{tokens: map[string]string{
			"eiam_sct_ecmdb_valid": "ecmdb",
		}}
		hdl := NewHandler(mockSvc, mockTk)

		engine := gin.New()
		hdl.PublicRoutes(engine)

		// 拿 ecmdb 的 Token 去上报 etask 资产
		reqBody, _ := json.Marshal(capability.SyncRequest{Service: "etask"})
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/discovery/sync", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer eiam_sct_ecmdb_valid")

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "通信令牌与上报服务标识不匹配")
		assert.Equal(t, 0, mockSvc.syncCount)
	})
}


