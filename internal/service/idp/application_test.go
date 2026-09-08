package idp

import (
	"context"
	"errors"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestApplicationService_Create(t *testing.T) {
	testCases := []struct {
		name       string
		mock       func(ctrl *gomock.Controller) *repomocks.MockIApplicationRepository
		reqApp     domain.Application
		wantErr    error
		checkAfter func(t *testing.T, created domain.Application)
	}{
		{
			name: "创建成功-自动填充默认值与生成密钥",
			mock: func(ctrl *gomock.Controller) *repomocks.MockIApplicationRepository {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
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
				return repo
			},
			reqApp: domain.Application{
				TenantID:     1,
				Name:         "Grafana",
				RedirectURIs: []string{"https://grafana.example.com/login/generic_oauth"},
			},
			checkAfter: func(t *testing.T, created domain.Application) {
				assert.Equal(t, int64(100), created.ID)
				assert.NotEmpty(t, created.ClientSecret)
				assert.True(t, created.VerifySecret(created.ClientSecret))
			},
		},
		{
			name: "创建失败-回调地址非法",
			mock: func(ctrl *gomock.Controller) *repomocks.MockIApplicationRepository {
				return repomocks.NewMockIApplicationRepository(ctrl)
			},
			reqApp: domain.Application{
				TenantID:     1,
				Name:         "Bad App",
				RedirectURIs: []string{"http://bad.com/#fragment"},
			},
			wantErr: errs.ErrInvalidRedirectURI,
		},
		{
			name: "创建失败-数据库错误",
			mock: func(ctrl *gomock.Controller) *repomocks.MockIApplicationRepository {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(int64(0), errors.New("db error"))
				return repo
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

			svc := NewApplicationService(tc.mock(ctrl))

			res, err := svc.Create(context.Background(), tc.reqApp)
			if tc.wantErr != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.checkAfter != nil {
					tc.checkAfter(t, res)
				}
			}
		})
	}
}

func TestApplicationService_Update(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) *repomocks.MockIApplicationRepository
		reqApp  domain.Application
		wantErr error
	}{
		{
			name: "更新成功",
			mock: func(ctrl *gomock.Controller) *repomocks.MockIApplicationRepository {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				repo.EXPECT().FindByID(gomock.Any(), int64(1)).Return(domain.Application{
					ID:       1,
					TenantID: 1,
					ClientID: "app_123",
				}, nil)
				repo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
				return repo
			},
			reqApp: domain.Application{
				ID:           1,
				Name:         "Grafana v2",
				RedirectURIs: []string{"https://grafana.example.com/callback"},
			},
		},
		{
			name: "更新失败-应用不存在",
			mock: func(ctrl *gomock.Controller) *repomocks.MockIApplicationRepository {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				repo.EXPECT().FindByID(gomock.Any(), int64(99)).Return(domain.Application{}, errs.ErrApplicationNotFound)
				return repo
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

			svc := NewApplicationService(tc.mock(ctrl))

			err := svc.Update(context.Background(), tc.reqApp)
			if tc.wantErr != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestApplicationService_ResetSecret(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) *repomocks.MockIApplicationRepository
		id      int64
		wantErr error
	}{
		{
			name: "重置成功",
			mock: func(ctrl *gomock.Controller) *repomocks.MockIApplicationRepository {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				repo.EXPECT().FindByID(gomock.Any(), int64(1)).Return(domain.Application{
					ID:       1,
					TenantID: 1,
					ClientID: "app_123",
				}, nil)
				repo.EXPECT().UpdateSecret(gomock.Any(), int64(1), gomock.Any()).Return(nil)
				return repo
			},
			id: 1,
		},
		{
			name: "重置失败-应用不存在",
			mock: func(ctrl *gomock.Controller) *repomocks.MockIApplicationRepository {
				repo := repomocks.NewMockIApplicationRepository(ctrl)
				repo.EXPECT().FindByID(gomock.Any(), int64(99)).Return(domain.Application{}, errs.ErrApplicationNotFound)
				return repo
			},
			id:      99,
			wantErr: errs.ErrApplicationNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			svc := NewApplicationService(tc.mock(ctrl))

			secret, err := svc.ResetSecret(context.Background(), tc.id)
			if tc.wantErr != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, secret)
			}
		})
	}
}
