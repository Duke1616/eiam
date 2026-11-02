package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	pkgmiddleware "github.com/Duke1616/eiam/pkg/web/middleware"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func initTestRedis(t *testing.T) redis.Cmdable {
	dir, err := os.Getwd()
	require.NoError(t, err)

	viper.SetConfigFile(filepath.Join(dir, "../../config/config.yaml"))
	if err := viper.ReadInConfig(); err != nil {
		viper.SetConfigFile(filepath.Join(dir, "../config/config.yaml"))
		_ = viper.ReadInConfig()
	}

	type Config struct {
		Addr     string `mapstructure:"addr"`
		Password string `mapstructure:"password"`
		DB       int    `mapstructure:"db"`
	}
	var cfg Config
	require.NoError(t, viper.UnmarshalKey("redis", &cfg))

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	return client
}

func TestRateLimit_RealRedisIntegration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	client := initTestRedis(t)

	// 清理测试 Key
	defer func() {
		ctx := t.Context()
		iter := client.Scan(ctx, 0, "eiam:ratelimit:*", 0).Iterator()
		for iter.Next(ctx) {
			_ = client.Del(ctx, iter.Val())
		}
	}()

	// 初始化包级限流器单例 (模拟 ioc 启动行为，测试配置 DefaultRate=2)
	limiter := pkgmiddleware.InitDefaultRateLimiter(client, pkgmiddleware.Config{
		Enabled:     true,
		DefaultRate: 2,
	})
	require.NotNil(t, limiter)

	router := gin.New()

	// 1. 普通未注册限流的公开路由 (直通，无频控)
	router.GET("/api/user/oidc/render", func(c *gin.Context) {
		c.JSON(http.StatusOK, ginx.Result{Msg: "render success"})
	})

	// 2. 敏感认证子路由组 (无参 LimitAuth 自动从配置中读取 DefaultRate=2)
	authGroup := router.Group("/api/user", pkgmiddleware.LimitAuth())
	{
		authGroup.POST("/system/login", func(c *gin.Context) {
			c.JSON(http.StatusOK, ginx.Result{Msg: "login success"})
		})
	}

	testCases := []struct {
		name         string
		method       string
		path         string
		clientIP     string
		totalReqs    int
		expectStatus []int
	}{
		{
			name:         "未挂载限流的公开路由无限次通过",
			method:       http.MethodGet,
			path:         "/api/user/oidc/render",
			clientIP:     "10.0.0.99",
			totalReqs:    5,
			expectStatus: []int{http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK},
		},
		{
			name:         "子路由组显式声明限流的敏感登录接口(2次放行,第3次拦截429)",
			method:       http.MethodPost,
			path:         "/api/user/system/login",
			clientIP:     "10.0.0.88",
			totalReqs:    3,
			expectStatus: []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < tc.totalReqs; i++ {
				req := httptest.NewRequest(tc.method, tc.path, nil)
				req.Header.Set("X-Forwarded-For", tc.clientIP)
				w := httptest.NewRecorder()

				router.ServeHTTP(w, req)

				assert.Equal(t, tc.expectStatus[i], w.Code, "第 %d 次请求状态码不符合预期", i+1)

				if w.Code == http.StatusTooManyRequests {
					var res ginx.Result
					err := json.Unmarshal(w.Body.Bytes(), &res)
					require.NoError(t, err)
					assert.Equal(t, 429001, res.Code)
					assert.Equal(t, "请求过于频繁，请稍后重试", res.Msg)
				}
			}
		})
	}
}
