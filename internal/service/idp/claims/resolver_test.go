package claims

import (
	"context"
	"errors"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	permmocks "github.com/Duke1616/eiam/internal/service/permission/mocks"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestClaimsResolver_Resolve(t *testing.T) {
	testCases := []struct {
		name    string
		ref     IdentityRef
		opts    []ResolveOption
		mock    func(ctrl *gomock.Controller) (*repomocks.MockIUserRepository, *permmocks.MockIPermissionService)
		wantErr bool
		wantSub  string
		wantUser string
		wantName string
		wantRole []string
	}{
		{
			name: "默认全量解析-获取用户资料与有效角色",
			ref:  IdentityRef{TenantID: 10, UserID: 1001, Username: "alice"},
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIUserRepository, *permmocks.MockIPermissionService) {
				userRepo := repomocks.NewMockIUserRepository(ctrl)
				permSvc := permmocks.NewMockIPermissionService(ctrl)

				userRepo.EXPECT().
					FindById(gomock.Any(), int64(1001)).
					DoAndReturn(func(ctx context.Context, id int64) (domain.User, error) {
						// 验证 Resolver 内部正确注入了租户上下文
						assert.Equal(t, int64(10), ctxutil.GetTenantID(ctx).Int64())
						return domain.User{
							ID:       1001,
							Username: "alice",
							Email:    "alice@example.com",
							Profile:  domain.UserProfile{Nickname: "爱丽丝"},
						}, nil
					})

				permSvc.EXPECT().
					GetRolesForUser(gomock.Any(), "alice").
					DoAndReturn(func(ctx context.Context, username string) ([]string, error) {
						assert.Equal(t, int64(10), ctxutil.GetTenantID(ctx).Int64())
						return []string{"admin", "ops"}, nil
					})

				return userRepo, permSvc
			},
			wantSub:  "1001",
			wantUser: "alice",
			wantName: "爱丽丝",
			wantRole: []string{"admin", "ops"},
		},
		{
			name: "WithoutRoles-跳过角色查询",
			ref:  IdentityRef{TenantID: 5, UserID: 1002},
			opts: []ResolveOption{WithoutRoles()},
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIUserRepository, *permmocks.MockIPermissionService) {
				userRepo := repomocks.NewMockIUserRepository(ctrl)
				permSvc := permmocks.NewMockIPermissionService(ctrl)

				userRepo.EXPECT().FindById(gomock.Any(), int64(1002)).Return(domain.User{
					ID:       1002,
					Username: "bob",
					Profile:  domain.UserProfile{Nickname: "鲍勃"},
				}, nil)

				// permSvc 不应有任何调用

				return userRepo, permSvc
			},
			wantSub:  "1002",
			wantUser: "bob",
			wantName: "鲍勃",
			wantRole: nil,
		},
		{
			name: "WithUser-预置用户实体跳过 DB 查询",
			ref:  IdentityRef{TenantID: 1, UserID: 1003},
			opts: []ResolveOption{
				WithUser(domain.User{
					ID:       1003,
					Username: "carol",
					Profile:  domain.UserProfile{Nickname: "卡罗尔"},
				}),
			},
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIUserRepository, *permmocks.MockIPermissionService) {
				userRepo := repomocks.NewMockIUserRepository(ctrl)
				permSvc := permmocks.NewMockIPermissionService(ctrl)

				// userRepo 不应被调用
				permSvc.EXPECT().GetRolesForUser(gomock.Any(), "carol").Return([]string{"developer"}, nil)

				return userRepo, permSvc
			},
			wantSub:  "1003",
			wantUser: "carol",
			wantName: "卡罗尔",
			wantRole: []string{"developer"},
		},
		{
			name: "用户查询失败-直接返回错误",
			ref:  IdentityRef{TenantID: 2, UserID: 9999},
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIUserRepository, *permmocks.MockIPermissionService) {
				userRepo := repomocks.NewMockIUserRepository(ctrl)
				permSvc := permmocks.NewMockIPermissionService(ctrl)

				userRepo.EXPECT().FindById(gomock.Any(), int64(9999)).Return(domain.User{}, errors.New("db error"))

				return userRepo, permSvc
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			userRepo, permSvc := tc.mock(ctrl)
			resolver := NewClaimsResolver(userRepo, permSvc)

			// 调用方只需传入普通 ctx，租户注入由 Resolver 内部处理
			c, err := resolver.Resolve(context.Background(), tc.ref, tc.opts...)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.wantSub, c.Subject)
			assert.Equal(t, tc.wantUser, c.Username)
			assert.Equal(t, tc.wantName, c.Name)
			assert.Equal(t, tc.wantRole, c.Roles)
		})
	}
}
