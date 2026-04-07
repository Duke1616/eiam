package resource

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/pkg/utils"
)

// IResourceService 物理资源管理服务
type IResourceService interface {
	// CreateAPI 注册 API
	CreateAPI(ctx context.Context, a domain.API) (int64, error)
	// FindAPIByPath 根据路径查找 API (供权限决策使用)
	FindAPIByPath(ctx context.Context, service, method, path string) (domain.API, error)

	// SyncMenus 高性能同步菜单树资产
	SyncMenus(ctx context.Context, menus []*domain.Menu) error
	// ListAllMenus 获取系统中注册的所有全量菜单
	ListAllMenus(ctx context.Context) ([]domain.Menu, error)
	// ReorderMenu 菜单重排序：将 id 移动至 targetPid 下的 targetPosition 位置 (0-based)
	ReorderMenu(ctx context.Context, id, targetPid, targetPosition int64) error
}

type resourceService struct {
	repo repository.IResourceRepository
}

func NewResourceService(repo repository.IResourceRepository) IResourceService {
	return &resourceService{repo: repo}
}

func (s *resourceService) CreateAPI(ctx context.Context, a domain.API) (int64, error) {
	return s.repo.CreateAPI(ctx, a)
}

func (s *resourceService) FindAPIByPath(ctx context.Context, service, method, path string) (domain.API, error) {
	return s.repo.FindAPIByPath(ctx, service, method, path)
}

func (s *resourceService) SyncMenus(ctx context.Context, menus []*domain.Menu) error {
	return s.repo.SyncMenuTree(ctx, menus)
}

func (s *resourceService) ListAllMenus(ctx context.Context) ([]domain.Menu, error) {
	return s.repo.ListAllMenus(ctx)
}

func (s *resourceService) ReorderMenu(ctx context.Context, id, targetPid, targetPosition int64) error {
	// 1. 获取目标父节点下的所有菜单清单
	targetMenus, err := s.repo.ListMenusByParentID(ctx, targetPid)
	if err != nil {
		return err
	}

	// 2. 获取被拖拽菜单的详情
	draggedMenu, err := s.repo.GetMenu(ctx, id)
	if err != nil {
		return err
	}
	// 修正为目标父节点标识
	draggedMenu.ParentID = targetPid

	// 3. 构建排序引擎：定义重平衡时的基数分配策略 (index+1 * 1000)
	sorter := utils.NewSorter(func(m domain.Menu, idx int) domain.Menu {
		m.Sort = int64(idx+1) * utils.DefaultIndexGap
		m.ParentID = targetPid // 关键：确保重平衡时所有数据同步归位
		return m
	})

	// 4. 计算重排方案
	plan := sorter.PlanReorder(targetMenus, draggedMenu, targetPosition)

	// 5. 执行更新
	if plan.NeedRebalance {
		return s.repo.BatchUpdateMenuSort(ctx, plan.Items)
	}

	// 快速路径：原子更新 ParentID 与 SortKey
	return s.repo.UpdateMenuSort(ctx, id, targetPid, plan.NewSortKey)
}
