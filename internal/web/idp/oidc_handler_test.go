package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	idpsvc "github.com/Duke1616/eiam/internal/service/idp"
	idpmocks "github.com/Duke1616/eiam/internal/service/idp/mocks"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

// OIDCHandlerTestSuite 覆盖 OIDC 完整协议流程的 Handler 集成测试
type OIDCHandlerTestSuite struct {
	suite.Suite
	ctrl   *gomock.Controller
	svc    *idpmocks.MockIService
	server *gin.Engine
}

func (s *OIDCHandlerTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.svc = idpmocks.NewMockIService(s.ctrl)

	gin.SetMode(gin.TestMode)
	engine := gin.New()

	// 注入伪造的已登录 Session（uid=100, tenant_id=1, username=alice）
	sp := session.NewMemorySession(session.Claims{
		Uid: 100,
		Data: map[string]string{
			"username":  "alice",
			"tenant_id": "1",
		},
	})
	engine.Use(func(c *gin.Context) {
		c.Set("_session", sp)
		c.Next()
	})

	hdl := NewHandler(nil, s.svc)
	hdl.PublicRoutes(engine)
	s.server = engine
}

func (s *OIDCHandlerTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

// --- 1. Discovery 端点 ---

func (s *OIDCHandlerTestSuite) TestDiscovery() {
	s.svc.EXPECT().
		GetDiscoveryConfig(gomock.Any(), gomock.Any()).
		Return(domain.NewOidcDiscovery("https://eiam.example.com"))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	var disc domain.OidcDiscovery
	require.NoError(s.T(), json.NewDecoder(w.Body).Decode(&disc))
	assert.Contains(s.T(), disc.Issuer, "eiam.example.com")
	assert.NotEmpty(s.T(), disc.TokenEndpoint)
	assert.NotEmpty(s.T(), disc.JwksURI)
}

// --- 2. JWKS 端点 ---

func (s *OIDCHandlerTestSuite) TestJWKS() {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(s.T(), err)
	pubKey := jose.JSONWebKey{
		Key:       &priv.PublicKey,
		KeyID:     "eiam-key-1",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	s.svc.EXPECT().
		GetJWKS(gomock.Any()).
		Return(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubKey}})

	req := httptest.NewRequest(http.MethodGet, "/oauth/v2/jwks", nil)
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	var ks jose.JSONWebKeySet
	require.NoError(s.T(), json.NewDecoder(w.Body).Decode(&ks))
	assert.Len(s.T(), ks.Keys, 1)
	assert.Equal(s.T(), "eiam-key-1", ks.Keys[0].KeyID)
}

// --- 3. Authorize 端点 ---

func (s *OIDCHandlerTestSuite) TestAuthorize() {
	testCases := []struct {
		name         string
		queryParams  url.Values
		mockSetup    func()
		wantCode     int
		wantLocation string
	}{
		{
			name: "正常授权 - 自动同意，直接回跳带 code",
			queryParams: url.Values{
				"client_id":     {"app_backend"},
				"redirect_uri":  {"https://app.example.com/callback"},
				"response_type": {"code"},
				"scope":         {"openid profile"},
				"state":         {"xyz-state"},
			},
			mockSetup: func() {
				s.svc.EXPECT().
					Authorize(gomock.Any(), gomock.Any()).
					Return(&idpsvc.AuthorizeResult{
						RequireConsent: false,
						RedirectURL:    "https://app.example.com/callback?code=test_code_123&state=xyz-state",
					}, nil)
			},
			wantCode:     http.StatusFound,
			wantLocation: "https://app.example.com/callback?code=test_code_123&state=xyz-state",
		},
		{
			name: "需要用户授权确认 - 跳转 consent 页",
			queryParams: url.Values{
				"client_id":    {"third_party_app"},
				"redirect_uri": {"https://third.example.com/cb"},
				"scope":        {"openid"},
			},
			mockSetup: func() {
				s.svc.EXPECT().
					Authorize(gomock.Any(), gomock.Any()).
					Return(&idpsvc.AuthorizeResult{
						RequireConsent: true,
						ConsentID:      "consent_abc",
						RedirectURL:    "/oauth/v2/consent?consent_id=consent_abc",
					}, nil)
			},
			wantCode:     http.StatusFound,
			wantLocation: "/oauth/v2/consent?consent_id=consent_abc",
		},
		{
			name: "缺少 client_id 参数",
			queryParams: url.Values{
				"redirect_uri": {"https://app.example.com/callback"},
			},
			mockSetup: func() {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name: "授权失败 - client 不存在",
			queryParams: url.Values{
				"client_id":    {"not_exist"},
				"redirect_uri": {"https://app.example.com/callback"},
			},
			mockSetup: func() {
				s.svc.EXPECT().
					Authorize(gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("客户端不存在"))
			},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		tc := tc
		s.T().Run(tc.name, func(t *testing.T) {
			tc.mockSetup()
			req := httptest.NewRequest(http.MethodGet,
				"/oauth/v2/authorize?"+tc.queryParams.Encode(), nil)
			w := httptest.NewRecorder()
			s.server.ServeHTTP(w, req)

			assert.Equal(t, tc.wantCode, w.Code)
			if tc.wantLocation != "" {
				assert.Equal(t, tc.wantLocation, w.Header().Get("Location"))
			}
		})
	}
}

// --- 4. Token 端点 (authorization_code) ---

func (s *OIDCHandlerTestSuite) TestToken_AuthorizationCode() {
	testCases := []struct {
		name         string
		formData     url.Values
		useBasicAuth bool
		mockSetup    func()
		wantCode     int
		checkBody    func(t *testing.T, body []byte)
	}{
		{
			name: "授权码换 Token 成功",
			formData: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {"valid_code_abc"},
				"redirect_uri":  {"https://app.example.com/callback"},
				"client_id":     {"app_backend"},
				"client_secret": {"s3cr3t"},
			},
			mockSetup: func() {
				s.svc.EXPECT().
					ExchangeToken(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&domain.OidcTokenResult{
						AccessToken:  "access_token_xxx",
						TokenType:    "Bearer",
						ExpiresIn:    7200,
						IDToken:      "id_token_yyy",
						RefreshToken: "refresh_token_zzz",
						Scope:        "openid profile",
					}, nil)
			},
			wantCode: http.StatusOK,
			checkBody: func(t *testing.T, body []byte) {
				var result domain.OidcTokenResult
				require.NoError(t, json.Unmarshal(body, &result))
				assert.Equal(t, "access_token_xxx", result.AccessToken)
				assert.Equal(t, "Bearer", result.TokenType)
				assert.Equal(t, int64(7200), result.ExpiresIn)
				assert.NotEmpty(t, result.IDToken)
				assert.NotEmpty(t, result.RefreshToken)
			},
		},
		{
			name: "无效授权码 - 换 Token 失败",
			formData: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {"expired_code"},
				"client_id":     {"app_backend"},
				"client_secret": {"s3cr3t"},
			},
			mockSetup: func() {
				s.svc.EXPECT().
					ExchangeToken(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("授权码已失效"))
			},
			wantCode: http.StatusBadRequest,
			checkBody: func(t *testing.T, body []byte) {
				var resp map[string]string
				require.NoError(t, json.Unmarshal(body, &resp))
				assert.Equal(t, "invalid_grant", resp["error"])
			},
		},
		{
			name: "Basic Auth 提取客户端凭证",
			formData: url.Values{
				"grant_type": {"authorization_code"},
				"code":       {"valid_code_abc"},
			},
			useBasicAuth: true,
			mockSetup: func() {
				s.svc.EXPECT().
					ExchangeToken(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&domain.OidcTokenResult{
						AccessToken: "access_token_xxx",
						TokenType:   "Bearer",
						ExpiresIn:   7200,
					}, nil)
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		tc := tc
		s.T().Run(tc.name, func(t *testing.T) {
			tc.mockSetup()
			req := httptest.NewRequest(http.MethodPost, "/oauth/v2/token",
				strings.NewReader(tc.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.useBasicAuth {
				req.SetBasicAuth("app_backend", "s3cr3t")
			}
			w := httptest.NewRecorder()
			s.server.ServeHTTP(w, req)

			assert.Equal(t, tc.wantCode, w.Code)
			if w.Code == http.StatusOK {
				assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			}
			if tc.checkBody != nil {
				tc.checkBody(t, w.Body.Bytes())
			}
		})
	}
}

// --- 5. Token 端点 (refresh_token) ---

func (s *OIDCHandlerTestSuite) TestToken_RefreshToken() {
	s.svc.EXPECT().
		ExchangeToken(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&domain.OidcTokenResult{
			AccessToken:  "new_access_token",
			TokenType:    "Bearer",
			ExpiresIn:    7200,
			RefreshToken: "new_refresh_token",
			Scope:        "openid profile",
		}, nil)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"old_refresh_token"},
		"client_id":     {"app_backend"},
		"client_secret": {"s3cr3t"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/v2/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	var result domain.OidcTokenResult
	require.NoError(s.T(), json.NewDecoder(w.Body).Decode(&result))
	assert.Equal(s.T(), "new_access_token", result.AccessToken)
	assert.NotEqual(s.T(), "old_refresh_token", result.RefreshToken, "Token Rotation: RefreshToken 应已轮转")
}

// --- 6. UserInfo 端点 ---

func (s *OIDCHandlerTestSuite) TestUserInfo() {
	testCases := []struct {
		name       string
		authHeader string
		mockSetup  func()
		wantCode   int
		checkBody  func(t *testing.T, body []byte)
	}{
		{
			name:       "Bearer Token 有效，返回用户信息",
			authHeader: "Bearer valid_access_token",
			mockSetup: func() {
				s.svc.EXPECT().
					GetUserInfo(gomock.Any(), "valid_access_token").
					Return(&domain.OidcUserInfo{
						Subject:           "100",
						PreferredUsername: "alice",
						Email:             "alice@example.com",
						TenantID:          1,
					}, nil)
			},
			wantCode: http.StatusOK,
			checkBody: func(t *testing.T, body []byte) {
				var info domain.OidcUserInfo
				require.NoError(t, json.Unmarshal(body, &info))
				assert.Equal(t, "100", info.Subject)
				assert.Equal(t, "alice", info.PreferredUsername)
			},
		},
		{
			name:       "缺少 Authorization 头",
			authHeader: "",
			mockSetup:  func() {},
			wantCode:   http.StatusUnauthorized,
		},
		{
			name:       "Token 非 Bearer 格式",
			authHeader: "Basic dXNlcjpwYXNz",
			mockSetup:  func() {},
			wantCode:   http.StatusUnauthorized,
		},
		{
			name:       "Token 已被吊销",
			authHeader: "Bearer revoked_token",
			mockSetup: func() {
				s.svc.EXPECT().
					GetUserInfo(gomock.Any(), "revoked_token").
					Return(nil, fmt.Errorf("token 已被撤销"))
			},
			wantCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		tc := tc
		s.T().Run(tc.name, func(t *testing.T) {
			tc.mockSetup()
			req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			s.server.ServeHTTP(w, req)

			assert.Equal(t, tc.wantCode, w.Code)
			if tc.wantCode == http.StatusUnauthorized {
				assert.Contains(t, w.Header().Get("WWW-Authenticate"), "Bearer")
			}
			if tc.checkBody != nil {
				tc.checkBody(t, w.Body.Bytes())
			}
		})
	}
}

// --- 7. Revoke 端点 ---

func (s *OIDCHandlerTestSuite) TestRevoke() {
	testCases := []struct {
		name         string
		formData     url.Values
		useBasicAuth bool
		mockSetup    func()
		wantCode     int
	}{
		{
			name: "吊销 RefreshToken 成功 (RFC 7009)",
			formData: url.Values{
				"token":           {"refresh_token_to_revoke"},
				"token_type_hint": {"refresh_token"},
				"client_id":       {"app_backend"},
				"client_secret":   {"s3cr3t"},
			},
			mockSetup: func() {
				s.svc.EXPECT().
					RevokeToken(gomock.Any(), "refresh_token_to_revoke", "refresh_token", "app_backend", "s3cr3t").
					Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:         "通过 Basic Auth 吊销 Token",
			formData:     url.Values{"token": {"some_access_token"}},
			useBasicAuth: true,
			mockSetup: func() {
				s.svc.EXPECT().
					RevokeToken(gomock.Any(), "some_access_token", "", "app_backend", "s3cr3t").
					Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name: "客户端凭证错误 - 返回 400",
			formData: url.Values{
				"token":         {"token_xxx"},
				"client_id":     {"app_backend"},
				"client_secret": {"wrong_secret"},
			},
			mockSetup: func() {
				s.svc.EXPECT().
					RevokeToken(gomock.Any(), "token_xxx", "", "app_backend", "wrong_secret").
					Return(fmt.Errorf("客户端密钥错误"))
			},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		tc := tc
		s.T().Run(tc.name, func(t *testing.T) {
			tc.mockSetup()
			req := httptest.NewRequest(http.MethodPost, "/oauth/v2/revoke",
				strings.NewReader(tc.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.useBasicAuth {
				req.SetBasicAuth("app_backend", "s3cr3t")
			}
			w := httptest.NewRecorder()
			s.server.ServeHTTP(w, req)
			assert.Equal(t, tc.wantCode, w.Code)
		})
	}
}

// --- 8. Logout 端点 ---

func (s *OIDCHandlerTestSuite) TestLogout() {
	testCases := []struct {
		name         string
		query        string
		wantCode     int
		wantLocation string
		wantBody     string
	}{
		{
			name:         "携带 redirect_uri 和 state，注销后跳转",
			query:        "post_logout_redirect_uri=https://app.example.com/logged-out&state=logout-state",
			wantCode:     http.StatusFound,
			wantLocation: "https://app.example.com/logged-out?state=logout-state",
		},
		{
			name:     "不携带 redirect_uri，返回 JSON 成功消息",
			query:    "",
			wantCode: http.StatusOK,
			wantBody: "已成功注销登录态",
		},
	}

	for _, tc := range testCases {
		tc := tc
		s.T().Run(tc.name, func(t *testing.T) {
			path := "/oauth/v2/logout"
			if tc.query != "" {
				path += "?" + tc.query
			}
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			s.server.ServeHTTP(w, req)

			assert.Equal(t, tc.wantCode, w.Code)
			if tc.wantLocation != "" {
				assert.Equal(t, tc.wantLocation, w.Header().Get("Location"))
			}
			if tc.wantBody != "" {
				assert.Contains(t, w.Body.String(), tc.wantBody)
			}
		})
	}
}

// --- 9. Consent 流程 ---

func (s *OIDCHandlerTestSuite) TestConsent() {
	s.T().Run("GetConsent - 获取授权信息", func(t *testing.T) {
		s.svc.EXPECT().
			GetConsentInfo(gomock.Any(), "consent_abc").
			Return(&domain.ConsentInfo{
				ConsentID:  "consent_abc",
				ClientName: "第三方应用",
				Scopes:     []string{"openid", "profile"},
			}, nil)

		req := httptest.NewRequest(http.MethodGet, "/oauth/v2/consent?consent_id=consent_abc", nil)
		w := httptest.NewRecorder()
		s.server.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var info domain.ConsentInfo
		require.NoError(t, json.NewDecoder(w.Body).Decode(&info))
		assert.Equal(t, "consent_abc", info.ConsentID)
		assert.Equal(t, "第三方应用", info.ClientName)
	})

	s.T().Run("GetConsent - 缺少 consent_id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/v2/consent", nil)
		w := httptest.NewRecorder()
		s.server.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	s.T().Run("ConfirmConsent - 用户同意授权", func(t *testing.T) {
		s.svc.EXPECT().
			ConfirmConsent(gomock.Any(), "consent_abc", true).
			Return("https://app.example.com/callback?code=new_code&state=s1", nil)

		form := url.Values{"consent_id": {"consent_abc"}, "approved": {"true"}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/v2/consent",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Contains(t, w.Header().Get("Location"), "code=new_code")
	})

	s.T().Run("ConfirmConsent - 用户拒绝授权", func(t *testing.T) {
		s.svc.EXPECT().
			ConfirmConsent(gomock.Any(), "consent_xyz", false).
			Return("https://app.example.com/callback?error=access_denied", nil)

		form := url.Values{"consent_id": {"consent_xyz"}, "approved": {"false"}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/v2/consent",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.server.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Contains(t, w.Header().Get("Location"), "access_denied")
	})
}

// --- 10. 完整 OIDC 流程端到端 ---

// TestFullOIDCFlow 模拟完整授权码流程：
// Authorize → Token(code) → UserInfo → Revoke → Logout
func (s *OIDCHandlerTestSuite) TestFullOIDCFlow() {
	t := s.T()

	// Step 1: Authorize
	s.svc.EXPECT().Authorize(gomock.Any(), gomock.Any()).
		Return(&idpsvc.AuthorizeResult{
			RedirectURL: "https://app.example.com/callback?code=flow_code_001&state=flow-state",
		}, nil)

	authW := httptest.NewRecorder()
	s.server.ServeHTTP(authW, httptest.NewRequest(http.MethodGet,
		"/oauth/v2/authorize?client_id=app&redirect_uri=https://app.example.com/callback&scope=openid+profile&state=flow-state", nil))
	require.Equal(t, http.StatusFound, authW.Code)
	parsed, _ := url.Parse(authW.Header().Get("Location"))
	code := parsed.Query().Get("code")
	require.Equal(t, "flow_code_001", code)

	// Step 2: Token(code)
	s.svc.EXPECT().ExchangeToken(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&domain.OidcTokenResult{
			AccessToken:  "flow_access_token",
			TokenType:    "Bearer",
			ExpiresIn:    7200,
			IDToken:      "flow_id_token",
			RefreshToken: "flow_refresh_token",
			Scope:        "openid profile",
		}, nil)

	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"app"}, "client_secret": {"secret"}}
	tokenW := httptest.NewRecorder()
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth/v2/token",
		strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.server.ServeHTTP(tokenW, tokenReq)
	require.Equal(t, http.StatusOK, tokenW.Code)

	var tokenResult domain.OidcTokenResult
	require.NoError(t, json.NewDecoder(tokenW.Body).Decode(&tokenResult))
	accessToken := tokenResult.AccessToken
	require.NotEmpty(t, accessToken)

	// Step 3: UserInfo
	s.svc.EXPECT().GetUserInfo(gomock.Any(), accessToken).
		Return(&domain.OidcUserInfo{
			Subject: "100", PreferredUsername: "alice", Email: "alice@example.com",
		}, nil)

	userInfoReq := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	userInfoReq.Header.Set("Authorization", "Bearer "+accessToken)
	userInfoW := httptest.NewRecorder()
	s.server.ServeHTTP(userInfoW, userInfoReq)
	require.Equal(t, http.StatusOK, userInfoW.Code)
	var userInfo domain.OidcUserInfo
	require.NoError(t, json.NewDecoder(userInfoW.Body).Decode(&userInfo))
	assert.Equal(t, "alice", userInfo.PreferredUsername)

	// Step 4: Revoke
	s.svc.EXPECT().RevokeToken(gomock.Any(), accessToken, "access_token", "app", "secret").Return(nil)
	revokeForm := url.Values{"token": {accessToken}, "token_type_hint": {"access_token"},
		"client_id": {"app"}, "client_secret": {"secret"}}
	revokeReq := httptest.NewRequest(http.MethodPost, "/oauth/v2/revoke",
		strings.NewReader(revokeForm.Encode()))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeW := httptest.NewRecorder()
	s.server.ServeHTTP(revokeW, revokeReq)
	assert.Equal(t, http.StatusOK, revokeW.Code)

	// Step 5: Logout
	logoutW := httptest.NewRecorder()
	s.server.ServeHTTP(logoutW, httptest.NewRequest(http.MethodGet,
		"/oauth/v2/logout?post_logout_redirect_uri=https://app.example.com/loggedout", nil))
	assert.Equal(t, http.StatusFound, logoutW.Code)
	assert.Contains(t, logoutW.Header().Get("Location"), "loggedout")
}

// 启动 Suite
func TestOIDCHandlerTestSuite(t *testing.T) {
	session.SetDefaultProvider(&noopSessionProvider{})
	suite.Run(t, new(OIDCHandlerTestSuite))
}

// noopSessionProvider 测试用空 Session Provider
type noopSessionProvider struct{}

func (n *noopSessionProvider) NewSession(_ *gctx.Context, _ int64, _ map[string]string, _ map[string]any) (session.Session, error) {
	return nil, nil
}
func (n *noopSessionProvider) Get(ctx *gctx.Context) (session.Session, error) {
	if sess, ok := ctx.Get("_session"); ok {
		return sess.(session.Session), nil
	}
	return nil, fmt.Errorf("no session")
}
func (n *noopSessionProvider) UpdateClaims(_ *gctx.Context, _ session.Claims) error { return nil }
func (n *noopSessionProvider) RenewAccessToken(_ *gctx.Context) error               { return nil }
func (n *noopSessionProvider) Destroy(_ *gctx.Context) error                        { return nil }
