package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRateLimiter 模拟实现 IRateLimiter
type mockRateLimiter struct {
	authHandler gin.HandlerFunc
}

func (m *mockRateLimiter) Limit(rate int, interval time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

func (m *mockRateLimiter) LimitAuth(rates ...int) gin.HandlerFunc {
	if m.authHandler != nil {
		return m.authHandler
	}
	return func(c *gin.Context) { c.Next() }
}

func (m *mockRateLimiter) LimitWith(rate int, interval time.Duration, keyGen func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

func TestLimitAuth_TableDriven(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name           string
		setupMock      func() IRateLimiter
		requestPath    string
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "正常未超限放行",
			setupMock: func() IRateLimiter {
				return &mockRateLimiter{
					authHandler: func(c *gin.Context) { c.Next() },
				}
			},
			requestPath:    "/api/user/system/login",
			expectedStatus: http.StatusOK,
			expectedBody:   `"login_ok"`,
		},
		{
			name: "触发限流返回429与标准JSON",
			setupMock: func() IRateLimiter {
				return &mockRateLimiter{
					authHandler: func(c *gin.Context) {
						c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
							"code": 429001,
							"msg":  "请求过于频繁，请稍后重试",
						})
					},
				}
			},
			requestPath:    "/api/user/system/login",
			expectedStatus: http.StatusTooManyRequests,
			expectedBody:   `"code":429001`,
		},
		{
			name: "未启用限流(noopLimiter)安全直通",
			setupMock: func() IRateLimiter {
				return &noopLimiter{}
			},
			requestPath:    "/api/user/system/login",
			expectedStatus: http.StatusOK,
			expectedBody:   `"login_ok"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			SetDefaultRateLimiterForTest(tc.setupMock())

			router := gin.New()
			// 模拟 Handler 子 Group 挂载
			authGroup := router.Group("/api/user", LimitAuth())
			{
				authGroup.POST("/system/login", func(c *gin.Context) {
					c.JSON(http.StatusOK, "login_ok")
				})
			}

			req := httptest.NewRequest(http.MethodPost, tc.requestPath, nil)
			req.Header.Set("X-Forwarded-For", "192.168.1.100")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedStatus, w.Code)
			if tc.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tc.expectedBody)
			}
		})
	}
}

func TestNewRateLimiter_DisabledConfig(t *testing.T) {
	// 验证配置 enabled: false 时优雅回退到 noopLimiter
	limiter := InitDefaultRateLimiter(nil, Config{Enabled: false})
	assert.IsType(t, &noopLimiter{}, limiter)
}

func TestLimitWith_KeyGen(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var capturedKey atomic.Value

	limiter := NewRateLimiter(nil, Config{Enabled: true})
	router := gin.New()

	// 验证自定义 Key 提取
	router.POST("/sms/send", limiter.LimitWith(1, time.Minute, func(c *gin.Context) string {
		key := "sms:" + c.Query("phone")
		capturedKey.Store(key)
		return key
	}), func(c *gin.Context) {
		c.JSON(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodPost, "/sms/send?phone=13800000000", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}
