package user

import (
	"context"
	"testing"
	"time"

	"github.com/Duke1616/ecmdb/pkg/cryptox"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	auditevt "github.com/Duke1616/eiam/internal/event/audit"
	auditmocks "github.com/Duke1616/eiam/internal/event/audit/mocks"
	"github.com/Duke1616/eiam/internal/repository"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	"github.com/Duke1616/eiam/internal/service/tenant"
	tenantmocks "github.com/Duke1616/eiam/internal/service/tenant/mocks"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthCoordinator_Authenticate(t *testing.T) {
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("correct_password"), bcrypt.DefaultCost)

	aliceUser := domain.User{
		ID:       101,
		Username: "alice",
		Password: string(passwordHash),
		Source:   domain.SourceLocal,
	}

	bobMfaUser := domain.User{
		ID:        102,
		Username:  "bob_mfa",
		Password:  string(passwordHash),
		Source:    domain.SourceLocal,
		MfaType:   "totp",
		MfaSecret: "encrypted_secret",
	}

	oidcUser := domain.User{
		ID:       103,
		Username: "charlie_oidc",
		Source:   domain.Source("oidc"),
	}

	testCases := []struct {
		name       string
		mock       func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService)
		authType   string
		payload    any

		wantResult domain.LoginResult
		wantErr    error
	}{
		{
			name: "本地账密认证成功出单",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().FindByUsername(gomock.Any(), "alice").Return(aliceUser, nil)
				repo.EXPECT().UpdateLastLoginAt(gomock.Any(), int64(101), gomock.Any()).Return(nil)
				tenantSvc.EXPECT().GetTenantsByUserId(gomock.Any(), int64(101)).Return([]domain.Tenant{
					{ID: ctxutil.SystemTenantID, Name: "系统管理租户"},
				}, nil)
				repo.EXPECT().FindById(gomock.Any(), int64(101)).Return(aliceUser, nil)

				return repo, tenantSvc
			},
			authType:   "local",
			payload:    PasswordCredential{Username: "alice", Password: "correct_password"},
			wantResult: domain.LoginResult{
				User:        aliceUser,
				TenantID:    ctxutil.SystemTenantID,
				AuthType:    "local",
				MfaRequired: false,
			},
			wantErr: nil,
		},
		{
			name: "密码错误拒绝并阻断流水线",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().FindByUsername(gomock.Any(), "alice").Return(aliceUser, nil)
				return repo, tenantSvc
			},
			authType: "local",
			payload:  PasswordCredential{Username: "alice", Password: "wrong_password"},
			wantErr:  errs.ErrInvalidUser,
		},
		{
			name: "账号不存在拒绝",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().FindByUsername(gomock.Any(), "nobody").Return(domain.User{}, errs.ErrInvalidUser)
				return repo, tenantSvc
			},
			authType: "local",
			payload:  PasswordCredential{Username: "nobody", Password: "any_password"},
			wantErr:  errs.ErrInvalidUser,
		},
		{
			name: "用户开启MFA触发两阶段挑战中断",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().FindByUsername(gomock.Any(), "bob_mfa").Return(bobMfaUser, nil)
				repo.EXPECT().SetMfaToken(gomock.Any(), gomock.Any(), int64(102)).Return(nil)
				return repo, tenantSvc
			},
			authType: "local",
			payload:  PasswordCredential{Username: "bob_mfa", Password: "correct_password"},
			wantResult: domain.LoginResult{
				User:        bobMfaUser,
				AuthType:    "local",
				MfaRequired: true,
			},
			wantErr: nil,
		},
		{
			name: "Passkey免密认证成功出单",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().FindById(gomock.Any(), int64(101)).Return(aliceUser, nil)
				repo.EXPECT().UpdateLastLoginAt(gomock.Any(), int64(101), gomock.Any()).Return(nil)
				tenantSvc.EXPECT().GetTenantsByUserId(gomock.Any(), int64(101)).Return([]domain.Tenant{
					{ID: 1001, Name: "企业工作区"},
				}, nil)
				repo.EXPECT().FindById(gomock.Any(), int64(101)).Return(aliceUser, nil)

				return repo, tenantSvc
			},
			authType: domain.PASSKEY.String(),
			payload:  int64(101),
			wantResult: domain.LoginResult{
				User:        aliceUser,
				TenantID:    1001,
				AuthType:    domain.PASSKEY.String(),
				MfaRequired: false,
			},
			wantErr: nil,
		},
		{
			name: "OIDC单点登录已绑定用户成功出单",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().FindUserByIdentity(gomock.Any(), domain.OIDC.String(), "sub_oidc_123").Return(oidcUser, nil)
				repo.EXPECT().UpdateLastLoginAt(gomock.Any(), int64(103), gomock.Any()).Return(nil)
				tenantSvc.EXPECT().GetTenantsByUserId(gomock.Any(), int64(103)).Return([]domain.Tenant{
					{ID: 1001, Name: "OIDC租户"},
				}, nil)
				repo.EXPECT().FindById(gomock.Any(), int64(103)).Return(oidcUser, nil)

				return repo, tenantSvc
			},
			authType: domain.OIDC.String(),
			payload: domain.OidcIdentity{
				Provider:   domain.OIDC.String(),
				ExternalID: "sub_oidc_123",
				Username:   "charlie_oidc",
			},
			wantResult: domain.LoginResult{
				User:        oidcUser,
				TenantID:    1001,
				AuthType:    domain.OIDC.String(),
				MfaRequired: false,
			},
			wantErr: nil,
		},
		{
			name: "未注册的认证源返回ProviderNotFound",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)
				return repo, tenantSvc
			},
			authType: "unknown_provider",
			payload:  nil,
			wantErr:  errs.ErrProviderNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo, tenantSvc := tc.mock(ctrl)
			coordinator := NewAuthCoordinator(repo, tenantSvc, nil, nil, nil, nil)

			res, err := coordinator.Authenticate(context.Background(), tc.authType, tc.payload)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantResult.User.ID, res.User.ID)
			assert.Equal(t, tc.wantResult.AuthType, res.AuthType)
			assert.Equal(t, tc.wantResult.MfaRequired, res.MfaRequired)
			if !tc.wantResult.MfaRequired {
				assert.Equal(t, tc.wantResult.TenantID, res.TenantID)
			} else {
				assert.NotEmpty(t, res.MfaToken)
			}
		})
	}
}

func TestAuthCoordinator_ResolveMfaChallenge(t *testing.T) {
	// 准备固定 TOTP Secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "EIAM",
		AccountName: "bob",
	})
	require.NoError(t, err)
	plainSecret := key.Secret()

	// 模拟加密管理器
	cm := cryptox.NewCryptoManager("v1").Register("v1", cryptox.MustNewAESCryptoV2("01234567890123456789012345678901"))
	encryptedSecret, err := cm.Encrypt(plainSecret)
	require.NoError(t, err)

	validCode, err := totp.GenerateCode(plainSecret, time.Now().UTC())
	require.NoError(t, err)

	mfaUser := domain.User{
		ID:        201,
		Username:  "bob",
		MfaType:   "totp",
		MfaSecret: encryptedSecret,
		Source:    domain.SourceLocal,
	}

	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService)
		token   string
		code    string
		wantErr bool
	}{
		{
			name: "成功应答挑战并恢复出单",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().GetMfaToken(gomock.Any(), "token_123").Return(int64(201), nil)
				repo.EXPECT().FindById(gomock.Any(), int64(201)).Return(mfaUser, nil)
				repo.EXPECT().DeleteMfaToken(gomock.Any(), "token_123").Return(nil)
				repo.EXPECT().UpdateLastLoginAt(gomock.Any(), int64(201), gomock.Any()).Return(nil)
				tenantSvc.EXPECT().GetTenantsByUserId(gomock.Any(), int64(201)).Return([]domain.Tenant{
					{ID: 1, Name: "主租户"},
				}, nil)
				repo.EXPECT().FindById(gomock.Any(), int64(201)).Return(mfaUser, nil)

				return repo, tenantSvc
			},
			token:   "token_123",
			code:    validCode,
			wantErr: false,
		},
		{
			name: "挑战令牌已过期或无效",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().GetMfaToken(gomock.Any(), "invalid_token").Return(int64(0), errs.ErrMfaTokenNotFound)
				return repo, tenantSvc
			},
			token:   "invalid_token",
			code:    "123456",
			wantErr: true,
		},
		{
			name: "动态验证码错误记录失败尝试",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)

				repo.EXPECT().GetMfaToken(gomock.Any(), "token_123").Return(int64(201), nil)
				repo.EXPECT().FindById(gomock.Any(), int64(201)).Return(mfaUser, nil)
				repo.EXPECT().IncMfaAttempts(gomock.Any(), "token_123").Return(1, nil)
				return repo, tenantSvc
			},
			token:   "token_123",
			code:    "000000",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo, tenantSvc := tc.mock(ctrl)
			coordinator := NewAuthCoordinator(repo, tenantSvc, nil, cm, nil, nil)

			res, err := coordinator.ResolveMfaChallenge(context.Background(), tc.token, tc.code)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, int64(201), res.User.ID)
			assert.Equal(t, "local", res.AuthType)
			assert.Equal(t, int64(1), res.TenantID)
		})
	}
}

func TestAuthCoordinator_AuditLogs(t *testing.T) {
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("correct_password"), bcrypt.DefaultCost)
	aliceUser := domain.User{
		ID:       101,
		Username: "alice",
		Password: string(passwordHash),
		Source:   domain.SourceLocal,
	}

	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService, auditevt.IAuditProducer)
		execute func(c IAuthCoordinator)
	}{
		{
			name: "登出成功异步记录审计日志",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService, auditevt.IAuditProducer) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)
				auditProd := auditmocks.NewMockIAuditProducer(ctrl)

				auditProd.EXPECT().RecordAuth(gomock.Any(), gomock.Cond(func(x any) bool {
					log, ok := x.(domain.AuthLog)
					if !ok {
						return false
					}
					return log.AuthType == "logout" &&
						log.UserID == 101 &&
						log.TenantID == 3 &&
						log.Username == "alice" &&
						log.Status == domain.AuthStatusSuccess &&
						log.ClientIP == "127.0.0.1" &&
						log.UserAgent == "Mozilla/5.0"
				})).Return(nil)

				return repo, tenantSvc, auditProd
			},
			execute: func(c IAuthCoordinator) {
				ctx := ctxutil.WithClientInfo(context.Background(), "127.0.0.1", "Mozilla/5.0")
				c.RecordLogout(ctx, 101, 3, "alice")
			},
		},
		{
			name: "登录成功内部流水线自动闭环记录审计日志",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService, auditevt.IAuditProducer) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)
				auditProd := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().FindByUsername(gomock.Any(), "alice").Return(aliceUser, nil)
				repo.EXPECT().UpdateLastLoginAt(gomock.Any(), int64(101), gomock.Any()).Return(nil)
				tenantSvc.EXPECT().GetTenantsByUserId(gomock.Any(), int64(101)).Return([]domain.Tenant{
					{ID: 3, Name: "研发租户"},
				}, nil)
				repo.EXPECT().FindById(gomock.Any(), int64(101)).Return(aliceUser, nil)

				auditProd.EXPECT().RecordAuth(gomock.Any(), gomock.Cond(func(x any) bool {
					log, ok := x.(domain.AuthLog)
					if !ok {
						return false
					}
					return log.AuthType == "local" &&
						log.UserID == 101 &&
						log.TenantID == 3 &&
						log.Username == "alice" &&
						log.Status == domain.AuthStatusSuccess &&
						log.ClientIP == "10.0.0.1" &&
						log.UserAgent == "Chrome/120.0"
				})).Return(nil)

				return repo, tenantSvc, auditProd
			},
			execute: func(c IAuthCoordinator) {
				ctx := ctxutil.WithClientInfo(context.Background(), "10.0.0.1", "Chrome/120.0")
				_, err := c.Authenticate(ctx, "local", PasswordCredential{Username: "alice", Password: "correct_password"})
				require.NoError(t, err)
			},
		},
		{
			name: "登录失败自动闭环记录安全风控日志",
			mock: func(ctrl *gomock.Controller) (repository.IUserRepository, tenant.ITenantService, auditevt.IAuditProducer) {
				repo := repomocks.NewMockIUserRepository(ctrl)
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)
				auditProd := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().FindByUsername(gomock.Any(), "alice").Return(domain.User{}, errs.ErrInvalidUser)

				auditProd.EXPECT().RecordAuth(gomock.Any(), gomock.Cond(func(x any) bool {
					log, ok := x.(domain.AuthLog)
					if !ok {
						return false
					}
					return log.AuthType == "local" &&
						log.Username == "alice" &&
						log.Status == domain.AuthStatusFailed &&
						log.FailReason == "账号或密码错误" &&
						log.ClientIP == "192.168.1.100" &&
						log.UserAgent == "curl/7.68.0"
				})).Return(nil)

				return repo, tenantSvc, auditProd
			},
			execute: func(c IAuthCoordinator) {
				ctx := ctxutil.WithClientInfo(context.Background(), "192.168.1.100", "curl/7.68.0")
				_, err := c.Authenticate(ctx, "local", PasswordCredential{Username: "alice", Password: "bad_password"})
				require.Error(t, err)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo, tenantSvc, auditProd := tc.mock(ctrl)
			coordinator := NewAuthCoordinator(repo, tenantSvc, nil, nil, auditProd, nil)

			tc.execute(coordinator)
			time.Sleep(50 * time.Millisecond) // 等待异步协程 RecordAuth
		})
	}
}

