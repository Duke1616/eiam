package permission

import (
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/stretchr/testify/assert"
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
