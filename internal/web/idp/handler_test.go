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

	hdl := NewHandler(nil, nil, nil)
	assert.NotNil(t, hdl)

	// 测试公共路由注册不 panic
	hdl.PublicRoutes(server)

	// 测试私有路由注册不 panic
	hdl.PrivateRoutes(server)

	routes := server.Routes()
	assert.NotEmpty(t, routes)

	// 验证私有管理路由挂载与公开 OIDC/CAS 路由
	expectedPaths := []string{
		"/.well-known/openid-configuration",
		"/oauth/v2/jwks",
		"/oauth/v2/authorize",
		"/api/idp/consent",
		"/oauth/v2/token",
		"/oauth/v2/revoke",
		"/oauth/v2/logout",
		"/userinfo",
		"/cas/login",
		"/cas/serviceValidate",
		"/cas/p3/serviceValidate",
		"/cas/validate",
		"/cas/logout",
		"/api/idp/application/create",
		"/api/idp/application/update",
		"/api/idp/application/reset_secret/:id",
		"/api/idp/application/list",
		"/api/idp/application/delete/:id",
		"/api/idp/application/detail/:id",
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
	app := domain.Application{
		ID:            101,
		TenantID:      1,
		ClientID:      "app_test_123",
		ClientSecret:  "secret-plain",
		Protocol:      domain.ProtocolCAS,
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

	vo := hdl.toVO(app)
	assert.Equal(t, app.ID, vo.ID)
	assert.Equal(t, app.TenantID, vo.TenantID)
	assert.Equal(t, string(domain.ProtocolCAS), vo.Protocol)
	assert.Equal(t, app.ClientID, vo.ClientID)
	assert.Equal(t, app.ClientSecret, vo.ClientSecret)
	assert.Equal(t, app.Name, vo.Name)
	assert.Equal(t, app.RedirectURIs, vo.RedirectURIs)
	assert.Equal(t, app.Scopes, vo.Scopes)
	assert.Equal(t, app.IsPublic, vo.IsPublic)
}
