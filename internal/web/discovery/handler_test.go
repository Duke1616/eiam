package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDiscoveryService struct {
	syncCount int
	lastHash  string
	tokens    map[string]string // token -> serviceName
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

func (m *mockDiscoveryService) GenerateToken(ctx context.Context, serviceName string) (string, error) {
	tok := "eiam_sct_test_" + serviceName
	m.tokens[tok] = serviceName
	return tok, nil
}

func (m *mockDiscoveryService) VerifyToken(ctx context.Context, token string) (string, error) {
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

		mockSvc := &mockDiscoveryService{tokens: make(map[string]string)}
		hdl := NewHandler(mockSvc, mockSvc)

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

		mockSvc := &mockDiscoveryService{tokens: make(map[string]string)}
		hdl := NewHandler(mockSvc, mockSvc)

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

		mockSvc := &mockDiscoveryService{tokens: make(map[string]string)}
		token, err := mockSvc.GenerateToken(context.Background(), "ecmdb")
		require.NoError(t, err)

		hdl := NewHandler(mockSvc, mockSvc)

		engine := gin.New()
		hdl.PublicRoutes(engine)

		reqBody, _ := json.Marshal(capability.SyncRequest{Service: "ecmdb"})
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/discovery/sync", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 1, mockSvc.syncCount)
	})

	t.Run("开启认证后，携带其他服务的 Token 尝试上报属于跨服务越权，应被拦截", func(t *testing.T) {
		viper.Set("discovery.auth_enabled", true)
		defer viper.Set("discovery.auth_enabled", false)

		mockSvc := &mockDiscoveryService{tokens: make(map[string]string)}
		// 为 order-service 生成了 token
		orderToken, err := mockSvc.GenerateToken(context.Background(), "order-service")
		require.NoError(t, err)

		hdl := NewHandler(mockSvc, mockSvc)

		engine := gin.New()
		hdl.PublicRoutes(engine)

		// 企图使用 order-service 的 token 上报 payment-service 的资产
		reqBody, _ := json.Marshal(capability.SyncRequest{Service: "payment-service"})
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/discovery/sync", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+orderToken)

		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// 检查返回自定义业务码 4060004 (ErrServiceMismatch)
		var resp struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, 4060004, resp.Code)
		assert.Equal(t, 0, mockSvc.syncCount) // 核心资产对账并未发生
	})
}
