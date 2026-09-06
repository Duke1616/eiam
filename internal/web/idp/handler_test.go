package idp

import (
	"testing"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandler_RouteRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := gin.New()

	hdl := NewHandler(nil, nil)
	assert.NotNil(t, hdl)

	// 测试公共路由注册不 panic
	hdl.PublicRoutes(server)

	// 测试私有路由注册不 panic
	hdl.PrivateRoutes(server)

	routes := server.Routes()
	assert.NotEmpty(t, routes)

	// 验证私有管理路由挂载与公开 OIDC 路由
	expectedPaths := []string{
		"/.well-known/openid-configuration",
		"/oauth/v2/jwks",
		"/oauth/v2/authorize",
		"/api/idp/consent",
		"/oauth/v2/token",
		"/oauth/v2/revoke",
		"/oauth/v2/logout",
		"/userinfo",
		"/api/idp/client/create",
		"/api/idp/client/update",
		"/api/idp/client/reset_secret/:id",
		"/api/idp/client/list",
		"/api/idp/client/delete/:id",
		"/api/idp/client/detail/:id",
	}

	for _, expected := range expectedPaths {
		found := false
		for _, r := range routes {
			if r.Path == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "缺少期望的路由路径: %s", expected)
	}
}

func TestHandler_ToVO(t *testing.T) {
	hdl := &Handler{}
	client := domain.OAuthClient{
		ID:            101,
		TenantID:      1,
		ClientID:      "app_test_123",
		ClientSecret:  "secret-plain",
		Name:          "测试应用",
		Logo:          "https://example.com/logo.png",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "profile"},
		IsPublic:      false,
		Ctime:         time.Now(),
		Utime:         time.Now(),
	}

	vo := hdl.toVO(client)
	assert.Equal(t, client.ID, vo.ID)
	assert.Equal(t, client.TenantID, vo.TenantID)
	assert.Equal(t, client.ClientID, vo.ClientID)
	assert.Equal(t, client.ClientSecret, vo.ClientSecret)
	assert.Equal(t, client.Name, vo.Name)
	assert.Equal(t, client.RedirectURIs, vo.RedirectURIs)
	assert.Equal(t, client.Scopes, vo.Scopes)
	assert.Equal(t, client.IsPublic, vo.IsPublic)
}
