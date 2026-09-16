package permission

import (
	"context"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/cache"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	resourcemocks "github.com/Duke1616/eiam/internal/service/resource/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestBuildGroupNodes(t *testing.T) {
	s := &permissionService{}

	testCases := []struct {
		name     string
		perms    []domain.Permission
		wantTree []domain.GroupNode
	}{
		{
			name: "单级与多级分组混合以及按MinSort物理注册顺序排序",
			perms: []domain.Permission{
				// 协作空间及其子组（Sort 为 20 级别，注册较晚）
				{Sort: 21, Code: "alert:workspace:add", Group: "协作空间"},
				{Sort: 20, Code: "alert:workspace:view", Group: "协作空间"},
				{Sort: 23, Code: "alert:workspace:suppression:add", Group: "协作空间/抑制规则管理"},
				{Sort: 22, Code: "alert:workspace:suppression:view", Group: "协作空间/抑制规则管理"},
				// 告警管理（Sort 为 10 级别，注册较早）
				{Sort: 10, Code: "alert:rule:view", Group: "告警管理/告警规则"},
			},
			wantTree: []domain.GroupNode{
				// 因为 告警管理 对应 action 的最小 Sort 为 10，小于 协作空间 的最小 Sort 20，
				// 所以即便在字母序中“告警管理”排在“协作空间”后面，在此也应该优先排在第一位。
				{
					Name: "告警管理",
					Children: []domain.GroupNode{
						{
							Name: "告警规则",
							Actions: []string{
								"alert:rule:view",
							},
						},
					},
				},
				{
					Name: "协作空间",
					Actions: []string{
						"alert:workspace:view",
						"alert:workspace:add",
					},
					Children: []domain.GroupNode{
						{
							Name: "抑制规则管理",
							Actions: []string{
								"alert:workspace:suppression:view",
								"alert:workspace:suppression:add",
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.buildGroupNodes(tc.perms)
			assert.Equal(t, tc.wantTree, got)
		})
	}
}

func TestPermissionService_GetPermissionManifest_Cache(t *testing.T) {
	testCases := []struct {
		name         string
		mock         func(ctrl *gomock.Controller) (*repomocks.MockIPermissionRepository, *resourcemocks.MockIResourceService)
		wantManifest domain.PermissionManifest
		wantErr      error
	}{
		{
			name: "缓存命中直接返回Manifest",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIPermissionRepository, *resourcemocks.MockIResourceService) {
				repo := repomocks.NewMockIPermissionRepository(ctrl)
				resSvc := resourcemocks.NewMockIResourceService(ctrl)
				repo.EXPECT().GetManifest(gomock.Any(), false).Return(domain.PermissionManifest{
					Permissions: []domain.Permission{{Code: "test:view", Name: "测试权限"}},
				}, nil)
				return repo, resSvc
			},
			wantManifest: domain.PermissionManifest{
				Permissions: []domain.Permission{{Code: "test:view", Name: "测试权限"}},
			},
			wantErr: nil,
		},
		{
			name: "缓存未命中拉取并成功回写缓存",
			mock: func(ctrl *gomock.Controller) (*repomocks.MockIPermissionRepository, *resourcemocks.MockIResourceService) {
				repo := repomocks.NewMockIPermissionRepository(ctrl)
				resSvc := resourcemocks.NewMockIResourceService(ctrl)
				repo.EXPECT().GetManifest(gomock.Any(), false).Return(domain.PermissionManifest{}, cache.ErrCacheNotFound)
				repo.EXPECT().ListAllPermissions(gomock.Any()).Return([]domain.Permission{
					{Service: "iam", Code: "test:view", Name: "测试权限", Scope: domain.ScopeTenant},
				}, nil)
				resSvc.EXPECT().ListServices(gomock.Any()).Return([]domain.Service{{Code: "iam", Name: "权限系统"}}, nil)
				repo.EXPECT().GetMenuBindings(gomock.Any()).Return(map[string][]string{}, nil)
				repo.EXPECT().SetManifest(gomock.Any(), false, gomock.Any()).Return(nil)
				return repo, resSvc
			},
			wantManifest: domain.PermissionManifest{
				Permissions: []domain.Permission{
					{Service: "iam", Code: "test:view", Name: "测试权限", Scope: domain.ScopeTenant},
				},
				Services: []domain.ServiceNode{
					{Code: "iam", Name: "权限系统", Groups: nil},
				},
			},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			repo, resSvc := tc.mock(ctrl)
			svc := &permissionService{
				permRepo:    repo,
				resourceSvc: resSvc,
			}

			manifest, err := svc.GetPermissionManifest(context.Background())
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantManifest, manifest)
			}
		})
	}
}
