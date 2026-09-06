package idp

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	auditmocks "github.com/Duke1616/eiam/internal/event/audit/mocks"
	cachemocks "github.com/Duke1616/eiam/internal/repository/cache/mocks"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	permmocks "github.com/Duke1616/eiam/internal/service/permission/mocks"
	tenantmocks "github.com/Duke1616/eiam/internal/service/tenant/mocks"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
)

func newTestKeyManager(t *testing.T) IKeyManager {
	km, err := NewKeyManager("test-key-1", "")
	require.NoError(t, err)
	return km
}

func TestService_Authorize_AutoConsent(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *cachemocks.MockIOidcCache, *tenantmocks.MockITenantService)
		req     AuthorizeRequest
		wantErr error
		check   func(t *testing.T, res *AuthorizeResult)
	}{
		{
			name: "第一方应用-自动授权生成Code",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *cachemocks.MockIOidcCache, *tenantmocks.MockITenantService) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				c := cachemocks.NewMockIOidcCache(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().FindByClientID(gomock.Any(), "client_1").Return(domain.OAuthClient{
					TenantID:     1,
					ClientID:     "client_1",
					AutoConsent:  true,
					RedirectURIs: []string{"https://app.example.com/callback"},
					Scopes:       []string{"openid", "profile"},
				}, nil)

				tenantSvc.EXPECT().CheckUserTenantAccess(gomock.Any(), int64(10)).Return(true, nil)
				c.EXPECT().SaveAuthCodeContext(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				return repo, c, tenantSvc
			},
			req: AuthorizeRequest{
				ClientID:     "client_1",
				RedirectURI:  "https://app.example.com/callback",
				ResponseType: "code",
				Scopes:       []string{"openid", "profile"},
				State:        "state_xyz",
				UserID:       10,
				Username:     "alice",
				TenantID:     1,
			},
			wantErr: nil,
			check: func(t *testing.T, res *AuthorizeResult) {
				assert.False(t, res.RequireConsent)
				assert.NotEmpty(t, res.RedirectURL)
				parsed, err := url.Parse(res.RedirectURL)
				assert.NoError(t, err)
				assert.NotEmpty(t, parsed.Query().Get("code"))
				assert.Equal(t, "state_xyz", parsed.Query().Get("state"))
			},
		},
		{
			name: "客户端不存在-返回错误",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *cachemocks.MockIOidcCache, *tenantmocks.MockITenantService) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				c := cachemocks.NewMockIOidcCache(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().FindByClientID(gomock.Any(), "unknown_client").Return(domain.OAuthClient{}, errs.ErrOAuthClientNotFound)

				return repo, c, tenantSvc
			},
			req: AuthorizeRequest{
				ClientID:    "unknown_client",
				RedirectURI: "https://app.example.com/callback",
			},
			wantErr: errs.ErrOAuthClientNotFound,
		},
		{
			name: "专属租户应用-用户跨活跃租户访问但拥有目标租户成员资格-准入成功并绑定应用租户",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *cachemocks.MockIOidcCache, *tenantmocks.MockITenantService) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				c := cachemocks.NewMockIOidcCache(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().FindByClientID(gomock.Any(), "tenant_10_app").Return(domain.OAuthClient{
					TenantID:     10,
					ClientID:     "tenant_10_app",
					AutoConsent:  true,
					RedirectURIs: []string{"https://app10.example.com/callback"},
					Scopes:       []string{"openid"},
				}, nil)

				// 校验用户是否为租户 10 的成员 (返回 true)
				tenantSvc.EXPECT().CheckUserTenantAccess(gomock.Any(), int64(100)).Return(true, nil)

				c.EXPECT().SaveAuthCodeContext(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, code string, data []byte) error {
						var authCode domain.AuthCode
						assert.NoError(t, json.Unmarshal(data, &authCode))
						// 确保签发出来的 AuthCode 中租户上下文绑定为应用所属租户 10，而非用户在主站活跃的租户 20
						assert.Equal(t, int64(10), authCode.TenantID)
						return nil
					},
				)

				return repo, c, tenantSvc
			},
			req: AuthorizeRequest{
				ClientID:     "tenant_10_app",
				RedirectURI:  "https://app10.example.com/callback",
				ResponseType: "code",
				Scopes:       []string{"openid"},
				UserID:       100,
				Username:     "bob",
				TenantID:     20, // 用户在主站会话处于租户 20
			},
			wantErr: nil,
			check: func(t *testing.T, res *AuthorizeResult) {
				assert.False(t, res.RequireConsent)
				assert.NotEmpty(t, res.RedirectURL)
			},
		},
		{
			name: "专属租户应用-用户非目标租户成员-准入被拒绝",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *cachemocks.MockIOidcCache, *tenantmocks.MockITenantService) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				c := cachemocks.NewMockIOidcCache(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().FindByClientID(gomock.Any(), "tenant_10_app").Return(domain.OAuthClient{
					TenantID:     10,
					ClientID:     "tenant_10_app",
					RedirectURIs: []string{"https://app10.example.com/callback"},
				}, nil)

				// 用户非租户 10 成员
				tenantSvc.EXPECT().CheckUserTenantAccess(gomock.Any(), int64(100)).Return(false, nil)

				return repo, c, tenantSvc
			},
			req: AuthorizeRequest{
				ClientID:    "tenant_10_app",
				RedirectURI: "https://app10.example.com/callback",
				UserID:      100,
				TenantID:    20,
			},
			wantErr: errs.ErrTenantAccessDenied,
		},
		{
			name: "系统租户应用-用户具备系统租户权限准入成功",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *cachemocks.MockIOidcCache, *tenantmocks.MockITenantService) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				c := cachemocks.NewMockIOidcCache(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().FindByClientID(gomock.Any(), "system_global_app").Return(domain.OAuthClient{
					TenantID:     1, // 系统根租户应用
					ClientID:     "system_global_app",
					AutoConsent:  true,
					RedirectURIs: []string{"https://gitlab.example.com/callback"},
					Scopes:       []string{"openid"},
				}, nil)

				tenantSvc.EXPECT().CheckUserTenantAccess(gomock.Any(), int64(100)).Return(true, nil)
				c.EXPECT().SaveAuthCodeContext(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				return repo, c, tenantSvc
			},
			req: AuthorizeRequest{
				ClientID:     "system_global_app",
				RedirectURI:  "https://gitlab.example.com/callback",
				ResponseType: "code",
				Scopes:       []string{"openid"},
				UserID:       100,
				Username:     "developer",
				TenantID:     20,
			},
			wantErr: nil,
			check: func(t *testing.T, res *AuthorizeResult) {
				assert.False(t, res.RequireConsent)
				assert.NotEmpty(t, res.RedirectURL)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo, oidcCache, tenantSvc := tc.mock(ctrl)
			userRepo := repomocks.NewMockIUserRepository(ctrl)
			permSvc := permmocks.NewMockIPermissionService(ctrl)
			audit := auditmocks.NewMockIAuditProducer(ctrl)
			km := newTestKeyManager(t)

			svc := NewService(repo, userRepo, permSvc, tenantSvc, oidcCache, km, audit)
			res, err := svc.Authorize(context.Background(), tc.req)
			if tc.wantErr != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.check != nil {
					tc.check(t, res)
				}
			}
		})
	}
}

func TestService_ConsentFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := repomocks.NewMockIOAuthClientRepository(ctrl)
	userRepo := repomocks.NewMockIUserRepository(ctrl)
	permSvc := permmocks.NewMockIPermissionService(ctrl)
	oidcCache := cachemocks.NewMockIOidcCache(ctrl)
	audit := auditmocks.NewMockIAuditProducer(ctrl)
	km := newTestKeyManager(t)

	audit.EXPECT().RecordOperation(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	consentInfo := domain.ConsentInfo{
		ConsentID:   "consent_123",
		ClientID:    "app_grafana",
		ClientName:  "Grafana",
		UserID:      101,
		Username:    "admin",
		TenantID:    1,
		RedirectURI: "https://grafana.example.com/callback",
		Scopes:      []string{"openid", "email"},
		State:       "state_111",
		CreatedAt:   time.Now().Unix(),
	}
	data, _ := json.Marshal(consentInfo)

	// 1. 获取 Consent 详情 (只读缓存)
	oidcCache.EXPECT().GetConsentContext(gomock.Any(), "consent_123").Return(data, nil)

	tenantSvc := tenantmocks.NewMockITenantService(ctrl)
	svc := NewService(repo, userRepo, permSvc, tenantSvc, oidcCache, km, audit)
	info, err := svc.GetConsentInfo(context.Background(), "consent_123")
	assert.NoError(t, err)
	assert.Equal(t, "Grafana", info.ClientName)

	// 2. 用户点击拒绝
	oidcCache.EXPECT().GetAndDelConsentContext(gomock.Any(), "consent_123").Return(data, nil)
	deniedURL, err := svc.ConfirmConsent(context.Background(), "consent_123", false)
	assert.NoError(t, err)
	assert.Contains(t, deniedURL, "error=access_denied")

	// 3. 用户点击同意
	oidcCache.EXPECT().GetAndDelConsentContext(gomock.Any(), "consent_123").Return(data, nil)
	oidcCache.EXPECT().SaveAuthCodeContext(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	approvedURL, err := svc.ConfirmConsent(context.Background(), "consent_123", true)
	assert.NoError(t, err)
	assert.Contains(t, approvedURL, "code=")
	assert.Contains(t, approvedURL, "state=state_111")
}

func TestService_ExchangeToken_RefreshToken_Rotation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := repomocks.NewMockIOAuthClientRepository(ctrl)
	userRepo := repomocks.NewMockIUserRepository(ctrl)
	permSvc := permmocks.NewMockIPermissionService(ctrl)
	tenantSvc := tenantmocks.NewMockITenantService(ctrl)
	oidcCache := cachemocks.NewMockIOidcCache(ctrl)
	audit := auditmocks.NewMockIAuditProducer(ctrl)
	km := newTestKeyManager(t)

	audit.EXPECT().RecordOperation(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	rawSecret := "secret_rot"
	hash, _ := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)

	repo.EXPECT().FindByClientID(gomock.Any(), "client_backend").Return(domain.OAuthClient{
		ClientID:         "client_backend",
		ClientSecretHash: string(hash),
		GrantTypes:       []string{"authorization_code", "refresh_token"},
		Scopes:           []string{"openid", "profile"},
	}, nil).AnyTimes()

	refreshSession := domain.RefreshTokenSession{
		RefreshToken: "old_refresh_token_123",
		ClientID:     "client_backend",
		UserID:       2001,
		Username:     "backend_user",
		TenantID:     1,
		Scopes:       []string{"openid", "profile"},
	}
	sessBytes, _ := json.Marshal(refreshSession)

	// 轮转校验：读取并删除旧 Token，写入新 Token
	oidcCache.EXPECT().GetRefreshToken(gomock.Any(), "old_refresh_token_123").Return(sessBytes, nil)
	oidcCache.EXPECT().DeleteRefreshToken(gomock.Any(), "old_refresh_token_123").Return(nil)
	oidcCache.EXPECT().SaveRefreshToken(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	oidcCache.EXPECT().TrackUserRefreshToken(gomock.Any(), "2001", gomock.Any()).Return(nil)

	permSvc.EXPECT().GetRolesForUser(gomock.Any(), "backend_user").Return([]string{"admin"}, nil)
	userRepo.EXPECT().FindById(gomock.Any(), int64(2001)).Return(domain.User{
		ID:       2001,
		Username: "backend_user",
		Email:    "backend@example.com",
	}, nil)

	svc := NewService(repo, userRepo, permSvc, tenantSvc, oidcCache, km, audit)

	res, err := svc.ExchangeToken(context.Background(), domain.TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     "client_backend",
		ClientSecret: rawSecret,
		RefreshToken: "old_refresh_token_123",
	}, "https://eiam.example.com")

	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
	assert.NotEqual(t, "old_refresh_token_123", res.RefreshToken)
}

func TestService_RevokeToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := repomocks.NewMockIOAuthClientRepository(ctrl)
	userRepo := repomocks.NewMockIUserRepository(ctrl)
	permSvc := permmocks.NewMockIPermissionService(ctrl)
	tenantSvc := tenantmocks.NewMockITenantService(ctrl)
	oidcCache := cachemocks.NewMockIOidcCache(ctrl)
	audit := auditmocks.NewMockIAuditProducer(ctrl)
	km := newTestKeyManager(t)

	audit.EXPECT().RecordOperation(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	rawSecret := "secret_rev"
	hash, _ := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)

	repo.EXPECT().FindByClientID(gomock.Any(), "client_rev").Return(domain.OAuthClient{
		ClientID:         "client_rev",
		ClientSecretHash: string(hash),
	}, nil)

	oidcCache.EXPECT().DeleteRefreshToken(gomock.Any(), "target_token").Return(nil)
	oidcCache.EXPECT().RevokeToken(gomock.Any(), "target_token", 24*time.Hour).Return(nil)

	svc := NewService(repo, userRepo, permSvc, tenantSvc, oidcCache, km, audit)

	err := svc.RevokeToken(context.Background(), "target_token", "refresh_token", "client_rev", rawSecret)
	assert.NoError(t, err)
}

func TestService_GetDiscoveryConfig(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil)

	t.Run("默认配置下不暴露 end_session 且标准暴露 revocation", func(t *testing.T) {
		viper.Set("idp.enable_slo", false)

		disc := svc.GetDiscoveryConfig(context.Background(), "https://eiam.example.com")
		assert.Empty(t, disc.EndSessionEndpoint)
		assert.Equal(t, "https://eiam.example.com/oauth/v2/revoke", disc.RevocationEndpoint)

		// 序列化后验证 JSON 中 omitempty
		raw, err := json.Marshal(disc)
		assert.NoError(t, err)
		assert.NotContains(t, string(raw), "end_session_endpoint")
		assert.Contains(t, string(raw), "revocation_endpoint")
	})

	t.Run("显式开启 SLO 时暴露端点", func(t *testing.T) {
		viper.Set("idp.enable_slo", true)
		disc := svc.GetDiscoveryConfig(context.Background(), "https://eiam.example.com")
		assert.Equal(t, "https://eiam.example.com/oauth/v2/logout", disc.EndSessionEndpoint)

		raw, err := json.Marshal(disc)
		assert.NoError(t, err)
		assert.Contains(t, string(raw), "end_session_endpoint")
	})
}
