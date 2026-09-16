package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/cache"
	cachemocks "github.com/Duke1616/eiam/internal/repository/cache/mocks"
	"github.com/Duke1616/eiam/internal/repository/dao"
	daomocks "github.com/Duke1616/eiam/internal/repository/dao/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestPermissionRepository_FindByActions(t *testing.T) {
	testCases := []struct {
		name      string
		mock      func(ctrl *gomock.Controller) (dao.IPermissionDAO, cache.IPermissionCache)
		actions   []string
		wantPerms []domain.Permission
		wantErr   error
	}{
		{
			name: "空动作列表直接返回nil",
			mock: func(ctrl *gomock.Controller) (dao.IPermissionDAO, cache.IPermissionCache) {
				return daomocks.NewMockIPermissionDAO(ctrl), cachemocks.NewMockIPermissionCache(ctrl)
			},
			actions:   []string{},
			wantPerms: nil,
			wantErr:   nil,
		},
		{
			name: "缓存命中直接返回",
			mock: func(ctrl *gomock.Controller) (dao.IPermissionDAO, cache.IPermissionCache) {
				d := daomocks.NewMockIPermissionDAO(ctrl)
				c := cachemocks.NewMockIPermissionCache(ctrl)
				c.EXPECT().GetPermissionsByActions(gomock.Any(), []string{"user:view"}).
					Return([]domain.Permission{
						{Code: "user:view", Name: "查看用户", Scope: domain.ScopeTenant},
					}, nil)
				return d, c
			},
			actions: []string{"user:view"},
			wantPerms: []domain.Permission{
				{Code: "user:view", Name: "查看用户", Scope: domain.ScopeTenant},
			},
			wantErr: nil,
		},
		{
			name: "缓存未命中并成功回写",
			mock: func(ctrl *gomock.Controller) (dao.IPermissionDAO, cache.IPermissionCache) {
				d := daomocks.NewMockIPermissionDAO(ctrl)
				c := cachemocks.NewMockIPermissionCache(ctrl)
				c.EXPECT().GetPermissionsByActions(gomock.Any(), []string{"user:create"}).
					Return(nil, cache.ErrCacheNotFound)
				d.EXPECT().FindByActions(gomock.Any(), []string{"user:create"}).
					Return([]dao.Permission{
						{Id: 1, Code: "user:create", Name: "创建用户", Scope: domain.ScopeSystem},
					}, nil)
				c.EXPECT().SetPermissionsByActions(gomock.Any(), []string{"user:create"}, []domain.Permission{
					{ID: 1, Code: "user:create", Name: "创建用户", Scope: domain.ScopeSystem},
				}).Return(nil)
				return d, c
			},
			actions: []string{"user:create"},
			wantPerms: []domain.Permission{
				{ID: 1, Code: "user:create", Name: "创建用户", Scope: domain.ScopeSystem},
			},
			wantErr: nil,
		},
		{
			name: "缓存未命中且DAO层查询报错",
			mock: func(ctrl *gomock.Controller) (dao.IPermissionDAO, cache.IPermissionCache) {
				d := daomocks.NewMockIPermissionDAO(ctrl)
				c := cachemocks.NewMockIPermissionCache(ctrl)
				c.EXPECT().GetPermissionsByActions(gomock.Any(), []string{"user:delete"}).
					Return(nil, cache.ErrCacheNotFound)
				d.EXPECT().FindByActions(gomock.Any(), []string{"user:delete"}).
					Return(nil, errors.New("db query failed"))
				return d, c
			},
			actions:   []string{"user:delete"},
			wantPerms: nil,
			wantErr:   errors.New("db query failed"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			d, c := tc.mock(ctrl)
			repo := NewPermissionRepository(d, c)

			got, err := repo.FindByActions(context.Background(), tc.actions)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantPerms, got)
			}
		})
	}
}

func TestPermissionRepository_ClearAllPermissionCaches(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	d := daomocks.NewMockIPermissionDAO(ctrl)
	c := cachemocks.NewMockIPermissionCache(ctrl)
	c.EXPECT().ClearAllPermissionCaches(gomock.Any()).Return(nil)

	repo := NewPermissionRepository(d, c)
	err := repo.ClearAllPermissionCaches(context.Background())
	assert.NoError(t, err)
}

func TestPermissionRepository_Manifest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	d := daomocks.NewMockIPermissionDAO(ctrl)
	c := cachemocks.NewMockIPermissionCache(ctrl)

	sample := domain.PermissionManifest{
		Permissions: []domain.Permission{{Code: "demo:view"}},
	}
	c.EXPECT().GetManifest(gomock.Any(), false).Return(sample, nil)
	c.EXPECT().SetManifest(gomock.Any(), false, sample).Return(nil)

	repo := NewPermissionRepository(d, c)

	got, err := repo.GetManifest(context.Background(), false)
	assert.NoError(t, err)
	assert.Equal(t, sample, got)

	err = repo.SetManifest(context.Background(), false, sample)
	assert.NoError(t, err)
}
