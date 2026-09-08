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

func TestApplicationService_CreateApplication(t *testing.T) {
	testCases := []struct {
		name       string
		mock       func(ctrl *gomock.Controller) (*repomocks.MockIApplicationRepository, *auditmocks.MockIAuditProducer)
		reqApp     domain.Application
		wantErr    error
		checkAfter func(t *testing.T, created domain.Application)
	}{
		{
			name: "创建成功-自动填充默认值与生成秘钥",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIApplicationRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().Create(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, a domain.Application) (int64, error) {
						assert.NotEmpty(t, a.ClientID)
						assert.NotEmpty(t, a.ClientSecret)
						assert.NotEmpty(t, a.ClientSecretHash)
						assert.Equal(t, []string{"code"}, a.ResponseTypes)
						assert.Equal(t, []string{"authorization_code", "refresh_token"}, a.GrantTypes)
						assert.Equal(t, []string{"openid", "profile", "email"}, a.Scopes)
						return int64(100), nil
					})

				audit.EXPECT().RecordOperation(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				return repo, audit
			},
			reqApp: domain.Application{
				TenantID:     1,
				Name:         "Grafana",
				RedirectURIs: []string{"https://grafana.example.com/login/generic_oauth"},
			},
			wantErr: nil,
			checkAfter: func(t *testing.T, created domain.Application) {
				assert.Equal(t, int64(100), created.ID)
				assert.NotEmpty(t, created.ClientSecret)
				assert.True(t, created.VerifySecret(created.ClientSecret))
			},
		},
		{
			name: "创建失败-回调地址非法",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIApplicationRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)
				return repo, audit
			},
			reqApp: domain.Application{
				TenantID:     1,
				Name:         "Bad App",
				RedirectURIs: []string{"http://bad.com/#fragment"}, // 带 Fragment 属于非法
			},
			wantErr: errs.ErrInvalidRedirectURI,
		},
		{
			name: "创建失败-数据库错误",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIApplicationRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(int64(0), errors.New("db error"))
				audit.EXPECT().RecordOperation(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				return repo, audit
			},
			reqApp: domain.Application{
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
			svc := NewApplicationService(repo, audit)

			res, err := svc.CreateApplication(context.Background(), tc.reqApp)
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

func TestApplicationService_UpdateApplication(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) (*repomocks.MockIApplicationRepository, *auditmocks.MockIAuditProducer)
		reqApp  domain.Application
		wantErr error
	}{
		{
			name: "更新成功",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIApplicationRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().FindByID(gomock.Any(), int64(1)).Return(domain.Application{
					ID:       1,
					TenantID: 1,
					ClientID: "app_123",
				}, nil)
				repo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
				audit.EXPECT().RecordOperation(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				return repo, audit
			},
			reqApp: domain.Application{
				ID:           1,
				Name:         "Grafana v2",
				RedirectURIs: []string{"https://grafana.example.com/callback"},
			},
			wantErr: nil,
		},
		{
			name: "更新失败-应用不存在",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIApplicationRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().FindByID(gomock.Any(), int64(99)).Return(domain.Application{}, errs.ErrApplicationNotFound)

				return repo, audit
			},
			reqApp: domain.Application{
				ID:           99,
				Name:         "Unknown",
				RedirectURIs: []string{"https://unknown.com/callback"},
			},
			wantErr: errs.ErrApplicationNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo, audit := tc.mock(ctrl)
			svc := NewApplicationService(repo, audit)

			err := svc.UpdateApplication(context.Background(), tc.reqApp)
			if tc.wantErr != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			time.Sleep(10 * time.Millisecond)
		})
	}
}

func TestApplicationService_ResetApplicationSecret(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) (*repomocks.MockIApplicationRepository, *auditmocks.MockIAuditProducer)
		id      int64
		wantErr error
	}{
		{
			name: "重置成功",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIApplicationRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().FindByID(gomock.Any(), int64(1)).Return(domain.Application{
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
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIApplicationRepository, *auditmocks.MockIAuditProducer) {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				audit := auditmocks.NewMockIAuditProducer(ctrl)

				repo.EXPECT().FindByID(gomock.Any(), int64(99)).Return(domain.Application{}, errs.ErrApplicationNotFound)

				return repo, audit
			},
			id:      99,
			wantErr: errs.ErrApplicationNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo, audit := tc.mock(ctrl)
			svc := NewApplicationService(repo, audit)

			secret, err := svc.ResetApplicationSecret(context.Background(), tc.id)
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
