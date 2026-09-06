package idp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	auditmocks "github.com/Duke1616/eiam/internal/event/audit/mocks"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestOAuthClientService_CreateClient(t *testing.T) {
	testCases := []struct {
		name       string
		mock       func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *auditmocks.MockIAuditProducer)
		reqClient  domain.OAuthClient
		wantErr    error
		checkAfter func(t *testing.T, created domain.OAuthClient)
	}{
		{
			name: "创建成功-自动填充默认值与生成秘钥",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().Create(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, c domain.OAuthClient) (int64, error) {
						assert.NotEmpty(t, c.ClientID)
						assert.NotEmpty(t, c.ClientSecret)
						assert.NotEmpty(t, c.ClientSecretHash)
						assert.Equal(t, []string{"code"}, c.ResponseTypes)
						assert.Equal(t, []string{"authorization_code", "refresh_token"}, c.GrantTypes)
						assert.Equal(t, []string{"openid", "profile", "email"}, c.Scopes)
						return int64(100), nil
					})

				audit.EXPECT().RecordOperation(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				return repo, audit
			},
			reqClient: domain.OAuthClient{
				TenantID:     1,
				Name:         "Grafana",
				RedirectURIs: []string{"https://grafana.example.com/login/generic_oauth"},
			},
			wantErr: nil,
			checkAfter: func(t *testing.T, created domain.OAuthClient) {
				assert.Equal(t, int64(100), created.ID)
				assert.NotEmpty(t, created.ClientSecret)
				assert.True(t, created.VerifySecret(created.ClientSecret))
			},
		},
		{
			name: "创建失败-回调地址非法",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)
				return repo, audit
			},
			reqClient: domain.OAuthClient{
				TenantID:     1,
				Name:         "Bad App",
				RedirectURIs: []string{"http://bad.com/#fragment"}, // 带 Fragment 属于非法
			},
			wantErr: errs.ErrInvalidRedirectURI,
		},
		{
			name: "创建失败-数据库错误",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(int64(0), errors.New("db error"))
				audit.EXPECT().RecordOperation(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				return repo, audit
			},
			reqClient: domain.OAuthClient{
				TenantID:     1,
				Name:         "Grafana",
				RedirectURIs: []string{"https://grafana.example.com/callback"},
			},
			wantErr: errors.New("db error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo, audit := tc.mock(ctrl)
			svc := NewOAuthClientService(repo, audit)

			res, err := svc.CreateClient(context.Background(), tc.reqClient)
			if tc.wantErr != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.checkAfter != nil {
					tc.checkAfter(t, res)
				}
			}
			time.Sleep(10 * time.Millisecond) // 等待异步审计
		})
	}
}

func TestOAuthClientService_UpdateClient(t *testing.T) {
	testCases := []struct {
		name      string
		mock      func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *auditmocks.MockIAuditProducer)
		reqClient domain.OAuthClient
		wantErr   error
	}{
		{
			name: "更新成功",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().FindByID(gomock.Any(), int64(1)).Return(domain.OAuthClient{
					ID:       1,
					TenantID: 1,
					ClientID: "app_123",
				}, nil)
				repo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
				audit.EXPECT().RecordOperation(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				return repo, audit
			},
			reqClient: domain.OAuthClient{
				ID:           1,
				Name:         "Grafana v2",
				RedirectURIs: []string{"https://grafana.example.com/callback"},
			},
			wantErr: nil,
		},
		{
			name: "更新失败-应用不存在",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().FindByID(gomock.Any(), int64(99)).Return(domain.OAuthClient{}, errs.ErrOAuthClientNotFound)

				return repo, audit
			},
			reqClient: domain.OAuthClient{
				ID:           99,
				Name:         "Unknown",
				RedirectURIs: []string{"https://unknown.com/callback"},
			},
			wantErr: errs.ErrOAuthClientNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo, audit := tc.mock(ctrl)
			svc := NewOAuthClientService(repo, audit)

			err := svc.UpdateClient(context.Background(), tc.reqClient)
			if tc.wantErr != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			time.Sleep(10 * time.Millisecond)
		})
	}
}

func TestOAuthClientService_ResetClientSecret(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *auditmocks.MockIAuditProducer)
		id      int64
		wantErr error
	}{
		{
			name: "重置成功",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().FindByID(gomock.Any(), int64(1)).Return(domain.OAuthClient{
					ID:       1,
					TenantID: 1,
					ClientID: "app_123",
				}, nil)
				repo.EXPECT().UpdateSecret(gomock.Any(), int64(1), gomock.Any()).Return(nil)
				audit.EXPECT().RecordOperation(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				return repo, audit
			},
			id:      1,
			wantErr: nil,
		},
		{
			name: "重置失败-不存在应用",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIOAuthClientRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIOAuthClientRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().FindByID(gomock.Any(), int64(99)).Return(domain.OAuthClient{}, errs.ErrOAuthClientNotFound)

				return repo, audit
			},
			id:      99,
			wantErr: errs.ErrOAuthClientNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo, audit := tc.mock(ctrl)
			svc := NewOAuthClientService(repo, audit)

			secret, err := svc.ResetClientSecret(context.Background(), tc.id)
			if tc.wantErr != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, secret)
			}
			time.Sleep(10 * time.Millisecond)
		})
	}
}
