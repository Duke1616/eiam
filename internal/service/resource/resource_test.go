package resource

import (
	"context"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeResourceRepo struct {
	repository.IResourceRepository
	menus map[int64]domain.Menu
}

func (f *fakeResourceRepo) GetMenu(ctx context.Context, id int64) (domain.Menu, error) {
	if m, ok := f.menus[id]; ok {
		return m, nil
	}
	return domain.Menu{}, errs.ErrDatabaseError
}

func (f *fakeResourceRepo) ListMenusByParentID(ctx context.Context, parentID int64) ([]domain.Menu, error) {
	var result []domain.Menu
	for _, m := range f.menus {
		if m.ParentID == parentID {
			result = append(result, m)
		}
	}
	return result, nil
}

func (f *fakeResourceRepo) UpdateMenuSort(ctx context.Context, id, parentID, sort int64) error {
	m, ok := f.menus[id]
	if ok {
		m.ParentID = parentID
		m.Sort = sort
		f.menus[id] = m
	}
	return nil
}

func (f *fakeResourceRepo) BatchUpdateMenuSort(ctx context.Context, items []domain.Menu) error {
	for _, item := range items {
		f.menus[item.ID] = item
	}
	return nil
}

func TestReorderMenuHierarchyProtection(t *testing.T) {
	testCases := []struct {
		name           string
		id             int64
		targetPid      int64
		targetPosition int64
		setupMenus     map[int64]domain.Menu
		expectedErr    error
	}{
		{
			name:           "禁止将自身设为父节点",
			id:             10,
			targetPid:      10,
			targetPosition: 0,
			setupMenus: map[int64]domain.Menu{
				10: {ID: 10, Name: "系统设置", ParentID: 0},
			},
			expectedErr: errs.ErrMenuSelfParent,
		},
		{
			name:           "禁止将父节点移动至直属子节点下产生闭环",
			id:             1,
			targetPid:      2,
			targetPosition: 0,
			setupMenus: map[int64]domain.Menu{
				1: {ID: 1, Name: "父目录", ParentID: 0},
				2: {ID: 2, Name: "子目录", ParentID: 1},
			},
			expectedErr: errs.ErrMenuCycleParent,
		},
		{
			name:           "禁止将祖先节点移动至深层后代节点下产生闭环",
			id:             1,
			targetPid:      3,
			targetPosition: 0,
			setupMenus: map[int64]domain.Menu{
				1: {ID: 1, Name: "根节点", ParentID: 0},
				2: {ID: 2, Name: "第一代子节点", ParentID: 1},
				3: {ID: 3, Name: "第二代孙节点", ParentID: 2},
			},
			expectedErr: errs.ErrMenuCycleParent,
		},
		{
			name:           "允许合法的同级移动",
			id:             2,
			targetPid:      0,
			targetPosition: 0,
			setupMenus: map[int64]domain.Menu{
				1: {ID: 1, Name: "菜单A", ParentID: 0, Sort: 1000},
				2: {ID: 2, Name: "菜单B", ParentID: 0, Sort: 2000},
			},
			expectedErr: nil,
		},
		{
			name:           "允许合法移动至另一个独立分支节点下",
			id:             3,
			targetPid:      2,
			targetPosition: 0,
			setupMenus: map[int64]domain.Menu{
				1: {ID: 1, Name: "分支A", ParentID: 0},
				2: {ID: 2, Name: "分支B", ParentID: 0},
				3: {ID: 3, Name: "分支A的子项", ParentID: 1},
			},
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeResourceRepo{menus: tc.setupMenus}
			svc := NewResourceService(repo, nil)

			err := svc.ReorderMenu(context.Background(), tc.id, tc.targetPid, tc.targetPosition)
			if tc.expectedErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
