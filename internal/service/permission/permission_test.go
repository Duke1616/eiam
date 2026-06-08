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
			name: "单级与多级分组混合及排序",
			perms: []domain.Permission{
				{Code: "alert:workspace:add", Group: "协作空间"},
				{Code: "alert:workspace:view", Group: "协作空间"},
				{Code: "alert:workspace:suppression:add", Group: "协作空间/抑制规则管理"},
				{Code: "alert:workspace:suppression:view", Group: "协作空间/抑制规则管理"},
				{Code: "alert:rule:view", Group: "告警管理/告警规则"},
			},
			wantTree: []domain.GroupNode{
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
