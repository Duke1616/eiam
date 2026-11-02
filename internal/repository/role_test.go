package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	cachemocks "github.com/Duke1616/eiam/internal/repository/cache/mocks"
	"github.com/Duke1616/eiam/internal/repository/dao"
	daomocks "github.com/Duke1616/eiam/internal/repository/dao/mocks"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestRoleRepository_GetByCode(t *testing.T) {
	testCases := []struct {
		name      string
		mock      func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache)
		ctx       context.Context
		code      string
		wantRole  domain.Role
		wantErr   error
	}{
		{
			name: "缓存命中-直接返回无需查库",
			mock: func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache) {
				d := daomocks.NewMockIRoleDAO(ctrl)
				c := cachemocks.NewMockIRoleCache(ctrl)

				c.EXPECT().GetRoleByCode(gomock.Any(), int64(100), "admin").
					Return(domain.Role{
						ID:   1,
						Code: "admin",
						Name: "超级管理员",
					}, true, nil)

				return d, c
			},
			ctx:  ctxutil.WithTenantID(context.Background(), 100),
			code: "admin",
			wantRole: domain.Role{
				ID:   1,
				Code: "admin",
				Name: "超级管理员",
			},
		},
		{
			name: "缓存未命中-查库成功并回填缓存",
			mock: func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache) {
				d := daomocks.NewMockIRoleDAO(ctrl)
				c := cachemocks.NewMockIRoleCache(ctrl)

				// 缓存未命中 (hit = false)
				c.EXPECT().GetRoleByCode(gomock.Any(), int64(100), "editor").
					Return(domain.Role{}, false, nil)

				// 查库
				d.EXPECT().GetByCode(gomock.Any(), "editor").
					Return(dao.Role{
						Id:       2,
						TenantId: 100,
						Code:     "editor",
						Name:     "编辑员",
						InlinePolicies: sqlx.JSONColumn[[]domain.Policy]{
							Val: []domain.Policy{
								{ID: 10, Name: "文章管理"},
							},
							Valid: true,
						},
					}, nil)

				// 回填缓存
				c.EXPECT().SetRoleByCode(gomock.Any(), int64(100), "editor", domain.Role{
					ID:       2,
					TenantID: 100,
					Code:     "editor",
					Name:     "编辑员",
					InlinePolicies: []domain.Policy{
						{ID: 10, Name: "文章管理"},
					},
				}).Return(nil)

				return d, c
			},
			ctx:  ctxutil.WithTenantID(context.Background(), 100),
			code: "editor",
			wantRole: domain.Role{
				ID:       2,
				TenantID: 100,
				Code:     "editor",
				Name:     "编辑员",
				InlinePolicies: []domain.Policy{
					{ID: 10, Name: "文章管理"},
				},
			},
		},
		{
			name: "缓存异常且数据库查询报错",
			mock: func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache) {
				d := daomocks.NewMockIRoleDAO(ctrl)
				c := cachemocks.NewMockIRoleCache(ctrl)

				c.EXPECT().GetRoleByCode(gomock.Any(), int64(100), "unknown").
					Return(domain.Role{}, false, errors.New("redis timeout"))

				d.EXPECT().GetByCode(gomock.Any(), "unknown").
					Return(dao.Role{}, errors.New("role not found"))

				return d, c
			},
			ctx:      ctxutil.WithTenantID(context.Background(), 100),
			code:     "unknown",
			wantRole: domain.Role{},
			wantErr:  errors.New("role not found"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			d, c := tc.mock(ctrl)
			repo := NewRoleRepository(d, c)

			role, err := repo.GetByCode(tc.ctx, tc.code)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantRole, role)
		})
	}
}

func TestRoleRepository_ListByIncludeCodes(t *testing.T) {
	testCases := []struct {
		name      string
		mock      func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache)
		ctx       context.Context
		codes     []string
		wantRoles []domain.Role
		wantErr   error
	}{
		{
			name: "全量命中缓存-零查库直出",
			mock: func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache) {
				d := daomocks.NewMockIRoleDAO(ctrl)
				c := cachemocks.NewMockIRoleCache(ctrl)

				c.EXPECT().GetRolesByCodes(gomock.Any(), int64(100), []string{"roleA", "roleB"}).
					Return(map[string]domain.Role{
						"roleA": {ID: 1, Code: "roleA", Name: "角色A"},
						"roleB": {ID: 2, Code: "roleB", Name: "角色B"},
					}, []string{}, nil)

				return d, c
			},
			ctx:   ctxutil.WithTenantID(context.Background(), 100),
			codes: []string{"roleA", "roleB"},
			wantRoles: []domain.Role{
				{ID: 1, Code: "roleA", Name: "角色A"},
				{ID: 2, Code: "roleB", Name: "角色B"},
			},
		},
		{
			name: "部分命中缓存-增量查库并回填未命中部分",
			mock: func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache) {
				d := daomocks.NewMockIRoleDAO(ctrl)
				c := cachemocks.NewMockIRoleCache(ctrl)

				// roleA 命中，roleB 未命中
				c.EXPECT().GetRolesByCodes(gomock.Any(), int64(100), []string{"roleA", "roleB"}).
					Return(map[string]domain.Role{
						"roleA": {ID: 1, Code: "roleA", Name: "角色A"},
					}, []string{"roleB"}, nil)

				// 仅对 roleB 下潜查库
				d.EXPECT().ListByIncludeCodes(gomock.Any(), []string{"roleB"}).
					Return([]dao.Role{
						{
							Id:       2,
							TenantId: 100,
							Code:     "roleB",
							Name:     "角色B",
						},
					}, nil)

				// 仅将加载出的 roleB 回填到缓存
				c.EXPECT().SetRoles(gomock.Any(), int64(100), []domain.Role{
					{ID: 2, TenantID: 100, Code: "roleB", Name: "角色B"},
				}).Return(nil)

				return d, c
			},
			ctx:   ctxutil.WithTenantID(context.Background(), 100),
			codes: []string{"roleA", "roleB"},
			wantRoles: []domain.Role{
				{ID: 1, Code: "roleA", Name: "角色A"},
				{ID: 2, TenantID: 100, Code: "roleB", Name: "角色B"},
			},
		},
		{
			name: "多租户优先级去重-DAO返回多条同Code记录优先保留私有角色",
			mock: func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache) {
				d := daomocks.NewMockIRoleDAO(ctrl)
				c := cachemocks.NewMockIRoleCache(ctrl)

				// 缓存均未命中
				c.EXPECT().GetRolesByCodes(gomock.Any(), int64(100), []string{"editor"}).
					Return(map[string]domain.Role{}, []string{"editor"}, nil)

				// DAO 返回两条：首条为租户私有角色 (tenant_id=100)，次条为平台全局角色 (tenant_id=1)
				d.EXPECT().ListByIncludeCodes(gomock.Any(), []string{"editor"}).
					Return([]dao.Role{
						{Id: 2, TenantId: 100, Code: "editor", Name: "租户私有编辑员"},
						{Id: 1, TenantId: 1, Code: "editor", Name: "平台全局编辑员"},
					}, nil)

				// 回填时应只回填私有角色
				c.EXPECT().SetRoles(gomock.Any(), int64(100), []domain.Role{
					{ID: 2, TenantID: 100, Code: "editor", Name: "租户私有编辑员"},
				}).Return(nil)

				return d, c
			},
			ctx:   ctxutil.WithTenantID(context.Background(), 100),
			codes: []string{"editor"},
			wantRoles: []domain.Role{
				{ID: 2, TenantID: 100, Code: "editor", Name: "租户私有编辑员"},
			},
		},
		{
			name: "空列表入参直接返回空",
			mock: func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache) {
				d := daomocks.NewMockIRoleDAO(ctrl)
				c := cachemocks.NewMockIRoleCache(ctrl)
				return d, c
			},
			ctx:       ctxutil.WithTenantID(context.Background(), 100),
			codes:     []string{},
			wantRoles: []domain.Role{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			d, c := tc.mock(ctrl)
			repo := NewRoleRepository(d, c)

			roles, err := repo.ListByIncludeCodes(tc.ctx, tc.codes)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantRoles, roles)
		})
	}
}

func TestRoleRepository_CacheInvalidation(t *testing.T) {
	testCases := []struct {
		name string
		op   func(t *testing.T, repo IRoleRepository, ctx context.Context)
		mock func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache)
		ctx  context.Context
	}{
		{
			name: "Update 成功淘汰单个角色缓存",
			mock: func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache) {
				d := daomocks.NewMockIRoleDAO(ctrl)
				c := cachemocks.NewMockIRoleCache(ctrl)

				d.EXPECT().Update(gomock.Any(), gomock.Any()).Return(int64(1), nil)
				c.EXPECT().DeleteRoleByCode(gomock.Any(), int64(100), "admin").Return(nil)

				return d, c
			},
			ctx: ctxutil.WithTenantID(context.Background(), 100),
			op: func(t *testing.T, repo IRoleRepository, ctx context.Context) {
				rows, err := repo.Update(ctx, domain.Role{Code: "admin", Name: "Admin"})
				assert.NoError(t, err)
				assert.Equal(t, int64(1), rows)
			},
		},
		{
			name: "UpdateInlinePolicies 成功淘汰角色缓存",
			mock: func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache) {
				d := daomocks.NewMockIRoleDAO(ctrl)
				c := cachemocks.NewMockIRoleCache(ctrl)

				d.EXPECT().UpdateInlinePolicies(gomock.Any(), "admin", gomock.Any()).Return(nil)
				c.EXPECT().DeleteRoleByCode(gomock.Any(), int64(100), "admin").Return(nil)

				return d, c
			},
			ctx: ctxutil.WithTenantID(context.Background(), 100),
			op: func(t *testing.T, repo IRoleRepository, ctx context.Context) {
				err := repo.UpdateInlinePolicies(ctx, "admin", []domain.Policy{{ID: 1}})
				assert.NoError(t, err)
			},
		},
		{
			name: "Delete 先获取 code 再删除并淘汰缓存",
			mock: func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache) {
				d := daomocks.NewMockIRoleDAO(ctrl)
				c := cachemocks.NewMockIRoleCache(ctrl)

				d.EXPECT().GetByID(gomock.Any(), int64(10)).
					Return(dao.Role{Id: 10, Code: "role_to_del"}, nil)
				d.EXPECT().Delete(gomock.Any(), int64(10)).Return(nil)
				c.EXPECT().DeleteRoleByCode(gomock.Any(), int64(100), "role_to_del").Return(nil)

				return d, c
			},
			ctx: ctxutil.WithTenantID(context.Background(), 100),
			op: func(t *testing.T, repo IRoleRepository, ctx context.Context) {
				err := repo.Delete(ctx, 10)
				assert.NoError(t, err)
			},
		},
		{
			name: "BatchDelete 先获取 codes 再批量删除并批量淘汰缓存",
			mock: func(ctrl *gomock.Controller) (dao.IRoleDAO, *cachemocks.MockIRoleCache) {
				d := daomocks.NewMockIRoleDAO(ctrl)
				c := cachemocks.NewMockIRoleCache(ctrl)

				d.EXPECT().FindByIDs(gomock.Any(), []int64{10, 11}).
					Return([]dao.Role{
						{Id: 10, Code: "role10"},
						{Id: 11, Code: "role11"},
					}, nil)
				d.EXPECT().DeleteByIDs(gomock.Any(), []int64{10, 11}).Return(int64(2), nil)
				c.EXPECT().DeleteRolesByCodes(gomock.Any(), int64(100), []string{"role10", "role11"}).Return(nil)

				return d, c
			},
			ctx: ctxutil.WithTenantID(context.Background(), 100),
			op: func(t *testing.T, repo IRoleRepository, ctx context.Context) {
				rows, err := repo.BatchDelete(ctx, []int64{10, 11})
				assert.NoError(t, err)
				assert.Equal(t, int64(2), rows)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			d, c := tc.mock(ctrl)
			repo := NewRoleRepository(d, c)
			tc.op(t, repo, tc.ctx)
		})
	}
}
