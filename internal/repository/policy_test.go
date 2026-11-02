package repository

import (
	"context"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/cache"
	cachemocks "github.com/Duke1616/eiam/internal/repository/cache/mocks"
	"github.com/Duke1616/eiam/internal/repository/dao"
	daomocks "github.com/Duke1616/eiam/internal/repository/dao/mocks"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestPolicyRepository_GetPolicyByCode(t *testing.T) {
	testCases := []struct {
		name       string
		code       string
		mock       func(ctrl *gomock.Controller) (dao.IPolicyDAO, cache.IPolicyCache)
		wantPolicy domain.Policy
		wantErr    error
	}{
		{
			name: "缓存命中直接返回",
			code: "policy-admin",
			mock: func(ctrl *gomock.Controller) (dao.IPolicyDAO, cache.IPolicyCache) {
				d := daomocks.NewMockIPolicyDAO(ctrl)
				c := cachemocks.NewMockIPolicyCache(ctrl)
				c.EXPECT().GetPolicyByCode(gomock.Any(), int64(1), "policy-admin").
					Return(domain.Policy{Code: "policy-admin", Name: "管理员策略"}, true, nil)
				return d, c
			},
			wantPolicy: domain.Policy{Code: "policy-admin", Name: "管理员策略"},
			wantErr:    nil,
		},
		{
			name: "缓存未命中查库并成功回写",
			code: "policy-editor",
			mock: func(ctrl *gomock.Controller) (dao.IPolicyDAO, cache.IPolicyCache) {
				d := daomocks.NewMockIPolicyDAO(ctrl)
				c := cachemocks.NewMockIPolicyCache(ctrl)
				c.EXPECT().GetPolicyByCode(gomock.Any(), int64(1), "policy-editor").
					Return(domain.Policy{}, false, nil)
				d.EXPECT().GetByCode(gomock.Any(), "policy-editor").
					Return(dao.Policy{
						Code: "policy-editor",
						Name: "编辑员策略",
						Document: sqlx.JSONColumn[[]domain.Statement]{
							Val:   []domain.Statement{{Effect: domain.Allow}},
							Valid: true,
						},
					}, nil)
				c.EXPECT().SetPolicyByCode(gomock.Any(), int64(1), "policy-editor", gomock.Any()).
					Return(nil)
				return d, c
			},
			wantPolicy: domain.Policy{
				Code:      "policy-editor",
				Name:      "编辑员策略",
				Statement: []domain.Statement{{Effect: domain.Allow}},
			},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			d, c := tc.mock(ctrl)
			repo := NewPolicyRepository(d, c)
			ctx := ctxutil.WithTenantID(context.Background(), 1)

			p, err := repo.GetPolicyByCode(ctx, tc.code)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantPolicy, p)
			}
		})
	}
}

func TestPolicyRepository_GetAttachedBySubjects(t *testing.T) {
	testCases := []struct {
		name        string
		subjects    []domain.Subject
		mock        func(ctrl *gomock.Controller) (dao.IPolicyDAO, cache.IPolicyCache)
		wantResult  map[string][]domain.Policy
		wantErr     error
	}{
		{
			name:     "全部命中主体挂载与详情缓存完全不查库",
			subjects: []domain.Subject{{Type: "user", ID: "alice"}},
			mock: func(ctrl *gomock.Controller) (dao.IPolicyDAO, cache.IPolicyCache) {
				d := daomocks.NewMockIPolicyDAO(ctrl)
				c := cachemocks.NewMockIPolicyCache(ctrl)
				// 第一阶段：命中挂载 codes
				c.EXPECT().GetAttachedCodes(gomock.Any(), int64(1), "user", "alice").
					Return([]string{"p1"}, true, nil)
				// 第二阶段：命中详情缓存
				c.EXPECT().GetPoliciesByCodes(gomock.Any(), int64(1), []string{"p1"}).
					Return(map[string]domain.Policy{"p1": {Code: "p1"}}, nil, nil)
				return d, c
			},
			wantResult: map[string][]domain.Policy{
				"user:alice": {{Code: "p1"}},
			},
			wantErr: nil,
		},
		{
			name:     "挂载缓存未命中查库并回填两级缓存防穿透",
			subjects: []domain.Subject{{Type: "user", ID: "bob"}},
			mock: func(ctrl *gomock.Controller) (dao.IPolicyDAO, cache.IPolicyCache) {
				d := daomocks.NewMockIPolicyDAO(ctrl)
				c := cachemocks.NewMockIPolicyCache(ctrl)
				// 第一阶段：挂载缓存未命中
				c.EXPECT().GetAttachedCodes(gomock.Any(), int64(1), "user", "bob").
					Return(nil, false, nil)
				// 查库获取分配关系
				d.EXPECT().GetCodesBySubjects(gomock.Any(), []domain.Subject{{Type: "user", ID: "bob"}}).
					Return([]dao.PolicyAssignment{
						{SubType: "user", SubCode: "bob", PolicyCode: "p2"},
					}, nil)
				// 回填挂载关系缓存
				c.EXPECT().SetAttachedCodes(gomock.Any(), int64(1), "user", "bob", []string{"p2"}).
					Return(nil)

				// 第二阶段：详情缓存未命中
				c.EXPECT().GetPoliciesByCodes(gomock.Any(), int64(1), []string{"p2"}).
					Return(map[string]domain.Policy{}, []string{"p2"}, nil)
				// 批量查库获取详情
				d.EXPECT().GetByCodes(gomock.Any(), []string{"p2"}).
					Return([]dao.Policy{
						{Code: "p2", Name: "普通策略"},
					}, nil)
				// 回填详情缓存
				c.EXPECT().SetPolicies(gomock.Any(), int64(1), []domain.Policy{
					{Code: "p2", Name: "普通策略"},
				}).Return(nil)

				return d, c
			},
			wantResult: map[string][]domain.Policy{
				"user:bob": {{Code: "p2", Name: "普通策略"}},
			},
			wantErr: nil,
		},
		{
			name:     "挂载缓存命中但详情被淘汰时精准从DB重新拉取最新策略(解决幽灵旧权限)",
			subjects: []domain.Subject{{Type: "role", ID: "admin"}},
			mock: func(ctrl *gomock.Controller) (dao.IPolicyDAO, cache.IPolicyCache) {
				d := daomocks.NewMockIPolicyDAO(ctrl)
				c := cachemocks.NewMockIPolicyCache(ctrl)
				// 第一阶段：挂载缓存依然有效
				c.EXPECT().GetAttachedCodes(gomock.Any(), int64(1), "role", "admin").
					Return([]string{"p_admin"}, true, nil)
				// 第二阶段：详情缓存因为管理员修改已被淘汰 (missingCodes 包含 p_admin)
				c.EXPECT().GetPoliciesByCodes(gomock.Any(), int64(1), []string{"p_admin"}).
					Return(map[string]domain.Policy{}, []string{"p_admin"}, nil)
				// 精准拉取最新策略详情
				d.EXPECT().GetByCodes(gomock.Any(), []string{"p_admin"}).
					Return([]dao.Policy{
						{Code: "p_admin", Name: "新管理员策略"},
					}, nil)
				// 回写最新策略详情缓存
				c.EXPECT().SetPolicies(gomock.Any(), int64(1), []domain.Policy{
					{Code: "p_admin", Name: "新管理员策略"},
				}).Return(nil)

				return d, c
			},
			wantResult: map[string][]domain.Policy{
				"role:admin": {{Code: "p_admin", Name: "新管理员策略"}},
			},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			d, c := tc.mock(ctrl)
			repo := NewPolicyRepository(d, c)
			ctx := ctxutil.WithTenantID(context.Background(), 1)

			res, err := repo.GetAttachedBySubjects(ctx, tc.subjects)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantResult, res)
			}
		})
	}
}

func TestPolicyRepository_Invalidations(t *testing.T) {
	t.Run("Attach解绑/绑定时精准淘汰主体挂载缓存", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := daomocks.NewMockIPolicyDAO(ctrl)
		c := cachemocks.NewMockIPolicyCache(ctrl)

		d.EXPECT().Bind(gomock.Any(), "user", "alice", "p1").Return(nil)
		c.EXPECT().DeleteAttached(gomock.Any(), int64(1), "user", "alice").Return(nil)

		d.EXPECT().Unbind(gomock.Any(), "user", "alice", "p1").Return(nil)
		c.EXPECT().DeleteAttached(gomock.Any(), int64(1), "user", "alice").Return(nil)

		repo := NewPolicyRepository(d, c)
		ctx := ctxutil.WithTenantID(context.Background(), 1)

		err := repo.Attach(ctx, "user", "alice", "p1")
		assert.NoError(t, err)

		err = repo.Detach(ctx, "user", "alice", "p1")
		assert.NoError(t, err)
	})

	t.Run("UpdatePolicy更新策略时精准淘汰详情缓存", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := daomocks.NewMockIPolicyDAO(ctrl)
		c := cachemocks.NewMockIPolicyCache(ctrl)

		d.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
		c.EXPECT().DeletePolicyByCode(gomock.Any(), int64(1), "p1").Return(nil)

		repo := NewPolicyRepository(d, c)
		ctx := ctxutil.WithTenantID(context.Background(), 1)

		err := repo.UpdatePolicy(ctx, domain.Policy{Code: "p1"})
		assert.NoError(t, err)
	})

	t.Run("BatchAttach批量绑定成功时精准淘汰受影响主体挂载缓存", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := daomocks.NewMockIPolicyDAO(ctrl)
		c := cachemocks.NewMockIPolicyCache(ctrl)

		subjects := []domain.Subject{{Type: "user", ID: "u1"}}
		policyCodes := []string{"p1", "p2"}

		d.EXPECT().BatchBind(gomock.Any(), gomock.Len(2)).Return(dao.BatchBindResult{Total: 2, Inserted: 2}, nil)
		c.EXPECT().DeleteAttachedBySubjects(gomock.Any(), int64(1), subjects).Return(nil)

		repo := NewPolicyRepository(d, c)
		ctx := ctxutil.WithTenantID(context.Background(), 1)

		res, err := repo.BatchAttach(ctx, subjects, policyCodes)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), res.Inserted)
	})

	t.Run("BatchDetach批量解绑成功时精准淘汰受影响主体挂载缓存", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := daomocks.NewMockIPolicyDAO(ctrl)
		c := cachemocks.NewMockIPolicyCache(ctrl)

		assignments := []domain.SubjectPolicyAssignment{
			{SubType: "user", SubCode: "u1", PolicyCode: "p1"},
			{SubType: "user", SubCode: "u1", PolicyCode: "p2"},
		}

		d.EXPECT().BatchUnbind(gomock.Any(), gomock.Len(2)).Return(int64(2), nil)
		c.EXPECT().DeleteAttachedBySubjects(gomock.Any(), int64(1), []domain.Subject{{Type: "user", ID: "u1"}}).Return(nil)

		repo := NewPolicyRepository(d, c)
		ctx := ctxutil.WithTenantID(context.Background(), 1)

		affected, err := repo.BatchDetach(ctx, assignments)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), affected)
	})

	t.Run("BatchDeletePolicies批量删除策略时批量淘汰详情缓存", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		d := daomocks.NewMockIPolicyDAO(ctrl)
		c := cachemocks.NewMockIPolicyCache(ctrl)

		codes := []string{"p1", "p2"}
		d.EXPECT().BatchDelete(gomock.Any(), codes).Return(nil)
		c.EXPECT().DeletePoliciesByCodes(gomock.Any(), int64(1), codes).Return(nil)

		repo := NewPolicyRepository(d, c)
		ctx := ctxutil.WithTenantID(context.Background(), 1)

		err := repo.BatchDeletePolicies(ctx, codes)
		assert.NoError(t, err)
	})
}
