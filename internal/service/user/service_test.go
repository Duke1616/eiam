package user

import (
	"context"
	"errors"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	"github.com/Duke1616/eiam/internal/service/tenant"
	tenantmocks "github.com/Duke1616/eiam/internal/service/tenant/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
)

func TestUserService_ValidatePassword(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		wantErr  error
	}{
		{
			name:     "默认规则 - 长度不足8位拒绝",
			password: "short",
			wantErr:  errs.ErrPasswordWeak,
		},
		{
			name:     "默认规则 - 满足8位通过",
			password: "password123",
			wantErr:  nil,
		},
	}

	svc := &userService{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.validatePassword(context.Background(), tc.password)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserService_List(t *testing.T) {
	mockUsers := []domain.User{
		{ID: 1, Username: "user1"},
		{ID: 2, Username: "user2"},
	}

	testCases := []struct {
		name      string
		mock      func(ctrl *gomock.Controller) repository.IUserRepository
		offset    int64
		limit     int64
		keyword   string
		wantUsers []domain.User
		wantTotal int64
		wantErr   error
	}{
		{
			name: "并发查询列表与总数成功",
			mock: func(ctrl *gomock.Controller) repository.IUserRepository {
				repo := repomocks.NewMockIUserRepository(ctrl)
				repo.EXPECT().List(gomock.Any(), int64(0), int64(10), "user").Return(mockUsers, nil)
				repo.EXPECT().Count(gomock.Any(), "user").Return(int64(2), nil)
				return repo
			},
			offset:    0,
			limit:     10,
			keyword:   "user",
			wantUsers: mockUsers,
			wantTotal: 2,
			wantErr:   nil,
		},
		{
			name: "查询列表失败触发联动取消并返回错误",
			mock: func(ctrl *gomock.Controller) repository.IUserRepository {
				repo := repomocks.NewMockIUserRepository(ctrl)
				repo.EXPECT().List(gomock.Any(), int64(0), int64(10), "").Return(nil, errors.New("db error"))
				repo.EXPECT().Count(gomock.Any(), "").Return(int64(0), nil).AnyTimes()
				return repo
			},
			offset:  0,
			limit:   10,
			keyword: "",
			wantErr: errors.New("db error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo := tc.mock(ctrl)
			svc := NewUserService(repo, nil, nil, nil)

			users, total, err := svc.List(context.Background(), tc.offset, tc.limit, tc.keyword)
			if tc.wantErr != nil {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantUsers, users)
			assert.Equal(t, tc.wantTotal, total)
		})
	}
}

func TestUserService_SwitchTenant(t *testing.T) {
	testCases := []struct {
		name           string
		mock           func(ctrl *gomock.Controller) tenant.ITenantService
		uid            int64
		targetTenantID int64
		wantErr        error
	}{
		{
			name: "拥有目标租户访问权",
			mock: func(ctrl *gomock.Controller) tenant.ITenantService {
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)
				tenantSvc.EXPECT().CheckUserTenantAccess(gomock.Any(), int64(100)).Return(true, nil)
				return tenantSvc
			},
			uid:            100,
			targetTenantID: 10,
			wantErr:        nil,
		},
		{
			name: "无目标租户访问权拦截",
			mock: func(ctrl *gomock.Controller) tenant.ITenantService {
				tenantSvc := tenantmocks.NewMockITenantService(ctrl)
				tenantSvc.EXPECT().CheckUserTenantAccess(gomock.Any(), int64(100)).Return(false, nil)
				return tenantSvc
			},
			uid:            100,
			targetTenantID: 20,
			wantErr:        errs.ErrTenantAccessDenied,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			tenantSvc := tc.mock(ctrl)
			svc := NewUserService(nil, tenantSvc, nil, nil)

			err := svc.SwitchTenant(context.Background(), tc.uid, tc.targetTenantID)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserService_Signup(t *testing.T) {
	testCases := []struct {
		name    string
		mock    func(ctrl *gomock.Controller) repository.IUserRepository
		user    domain.User
		wantID  int64
		wantErr error
	}{
		{
			name: "用户名已存在",
			mock: func(ctrl *gomock.Controller) repository.IUserRepository {
				repo := repomocks.NewMockIUserRepository(ctrl)
				repo.EXPECT().FindByUsername(gomock.Any(), "existing_user").Return(domain.User{ID: 1}, nil)
				return repo
			},
			user: domain.User{
				Username: "existing_user",
				Password: "Password123!",
			},
			wantErr: errs.ErrUserExist,
		},
		{
			name: "密码合规创建成功并加密存储",
			mock: func(ctrl *gomock.Controller) repository.IUserRepository {
				repo := repomocks.NewMockIUserRepository(ctrl)
				repo.EXPECT().FindByUsername(gomock.Any(), "new_user").Return(domain.User{}, errors.New("not found"))
				repo.EXPECT().Create(gomock.Any(), gomock.Cond(func(x any) bool {
					u, ok := x.(domain.User)
					if !ok {
						return false
					}
					// 验证入库密码已完成 bcrypt 加盐加密，非明文
					err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte("ValidPassword123"))
					return err == nil && u.Source == domain.SourceLocal && u.Status == domain.StatusActive
				})).Return(int64(999), nil)
				return repo
			},
			user: domain.User{
				Username: "new_user",
				Password: "ValidPassword123",
			},
			wantID:  999,
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo := tc.mock(ctrl)
			svc := NewUserService(repo, nil, nil, nil)

			id, err := svc.Signup(context.Background(), tc.user)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantID, id)
			}
		})
	}
}
