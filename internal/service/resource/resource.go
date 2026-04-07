package resource

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/pkg/utils"
)

// IResourceService 物理资源管理服务
// 负责维护系统中全量物理资产 (API, Menu) 的元数据底数
type IResourceService interface {
	// --- 1. 资产发现与检索 (Assets Discovery) ---

	// CreateAPI 注册一个新的物理接口资产
	CreateAPI(ctx context.Context, a domain.API) (int64, error)
	// FindAPIByPath 根据物理路径查找指定 API 资产
	FindAPIByPath(ctx context.Context, service, method, path string) (domain.API, error)

	// --- 2. 菜单层级管理 (Hierarchy Management) ---

	// SyncMenus 高性能同步菜单树状资产 (通常用于启动初始化)
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

// ReorderMenu 菜单重排序：实现跨节点拖拽与稀疏索引重新分配
func (s *resourceService) ReorderMenu(ctx context.Context, id, targetPid, targetPosition int64) error {
	// 1. 环境上下文：拉取目标组内所有现有菜单
	targetMenus, err := s.repo.ListMenusByParentID(ctx, targetPid)
	if err != nil {
		return err
	}

	// 2. 实体状态：获取并对齐被拖拽菜单的逻辑关系
	draggedMenu, err := s.repo.GetMenu(ctx, id)
	if err != nil {
		return err
	}
	draggedMenu.ParentID = targetPid

	// 3. 计算排程：利用通用 Sorter 引擎执行数学空间映射
	sorter := utils.NewSorter(func(m domain.Menu, idx int) domain.Menu {
		m.Sort = int64(idx+1) * utils.DefaultIndexGap
		m.ParentID = targetPid // NOTE: 确保重平衡时同步修正父子关联
		return m
	})

	// 4. 生成计划：判定采取单步偏移 (Fast) 还是全量对齐 (Slow)
	plan := sorter.PlanReorder(targetMenus, draggedMenu, targetPosition)

	// 5. 执行更新：基于计算出的计划选择最优落库策略
	if plan.NeedRebalance {
		return s.repo.BatchUpdateMenuSort(ctx, plan.Items)
	}

	// 快速路径：原子级别更新父节点归属与排序分值
	return s.repo.UpdateMenuSort(ctx, id, targetPid, plan.NewSortKey)
}
