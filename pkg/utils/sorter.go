package utils

import (
	"slices"

	"github.com/ecodeclub/ekit/slice"
)

const (
	// DefaultIndexGap 默认稀疏索引间隔，用于初始和重平衡分配
	DefaultIndexGap = 1000
)

// Sortable 可排序元素契约接口
// 用于通用排序引擎 Sorter 进行插值算法计算。
// 任何需要支持拖拽重排的业务实体（如 Menu, Role 等）均应实现此接口以接入 Sparse Index 排序体系。
type Sortable interface {
	// GetID 获取实体的唯一标识
	// 用于在列表中精确定位元素，并在组内或跨组移动时正确排除/插入该元素。
	GetID() int64
	// GetSortKey 获取当前的排序权重值
	// 该分值通常为 int64 以确保在高频率、密集插值场景下拥有足够的增长与分配空间。
	GetSortKey() int64
}

// ReorderPlan 重排执行计划
// NOTE: T 为具体业务定义的排序项类型（通常包含 ID 和新的 SortKey）
type ReorderPlan[T any] struct {
	// NeedRebalance 是否需要重平衡（当间隙耗尽时触发全量重排）
	NeedRebalance bool
	// NewSortKey 被拖拽元素的新 SortKey（快速路径：单条更新）
	NewSortKey int64
	// Items 重平衡模式下的批量更新列表（慢路径：全量更新）
	Items []T
}

// Sorter 通用重排序计算引擎
// NOTE: E 为实体类型(需实现 Sortable), T 为排序更新项类型
type Sorter[E Sortable, T any] struct {
	indexGap int64
	// convertFunc 转换函数，用于重平衡时将实体映射为更新项
	convertFunc func(elem E, idx int) T
}

// NewSorter 创建排序引擎
// convertFunc: 必须合理实现重平衡时的 SortKey 生成逻辑（如使用新的 index * indexGap）
func NewSorter[E Sortable, T any](convertFunc func(elem E, idx int) T) *Sorter[E, T] {
	return &Sorter[E, T]{
		indexGap:    DefaultIndexGap,
		convertFunc: convertFunc,
	}
}

// WithIndexGap 自定义稀疏间隔
func (s *Sorter[E, T]) WithIndexGap(gap int64) *Sorter[E, T] {
	s.indexGap = gap
	return s
}

// PlanReorder 计算重排执行计划（纯函数)
// elements: 目标作用域（如同级父节点下）的所有有序元素
// draggedElem: 当前被拖拽的元素
// targetPosition: 预期插入的 0-based 索引位置
func (s *Sorter[E, T]) PlanReorder(elements []E, draggedElem E, targetPosition int64) ReorderPlan[T] {
	// 1. 获取纯净的剩余列表（排除被拖拽元素本身，兼容跨组和组内拖拽）
	remainingElems := s.removeDragged(elements, draggedElem.GetID())

	// 2. 计算插值结果
	newSortKey := s.calculateSortKey(remainingElems, targetPosition)

	// 3. 冲突与重平衡检测
	if s.needsRebalance(remainingElems, targetPosition, newSortKey) {
		// 构造插入后的最终列表用于重平衡计算
		finalList := s.insertElem(remainingElems, draggedElem, targetPosition)

		return ReorderPlan[T]{
			NeedRebalance: true,
			Items:         s.Rebalance(finalList),
		}
	}

	// 快速路径：偏移量计算成功且间隙充足
	return ReorderPlan[T]{
		NeedRebalance: false,
		NewSortKey:    newSortKey,
	}
}

// removeDragged 移除被拖拽元素
func (s *Sorter[E, T]) removeDragged(elems []E, draggedId int64) []E {
	idx := slices.IndexFunc(elems, func(e E) bool {
		return e.GetID() == draggedId
	})
	if idx == -1 {
		return elems
	}
	return slices.Delete(slices.Clone(elems), idx, idx+1)
}

// insertElem 将元素插入到模拟位置
func (s *Sorter[E, T]) insertElem(elems []E, elem E, position int64) []E {
	if position < 0 {
		position = 0
	}
	if position > int64(len(elems)) {
		position = int64(len(elems))
	}
	return slices.Insert(slices.Clone(elems), int(position), elem)
}

// calculateSortKey 稀疏索引中值插值算法
func (s *Sorter[E, T]) calculateSortKey(elems []E, position int64) int64 {
	n := int64(len(elems))

	// 情况 A: 插入到空列表或末尾
	if n == 0 || position >= n {
		if n == 0 {
			return s.indexGap
		}
		return elems[n-1].GetSortKey() + s.indexGap
	}

	// 情况 B: 插入到开头（取首项半值）
	if position == 0 {
		return elems[0].GetSortKey() / 2
	}

	// 情况 C: 插入到中间（取前后均值）
	return (elems[position-1].GetSortKey() + elems[position].GetSortKey()) / 2
}

// needsRebalance 重平衡检测逻辑 (修复版)
func (s *Sorter[E, T]) needsRebalance(remaining []E, position, newSortKey int64) bool {
	// 边界：头部插值耗尽（归零）
	if position == 0 && newSortKey <= 0 {
		return true
	}

	// 中间插值冲突（间隙消失）
	if position > 0 && position < int64(len(remaining)) {
		return newSortKey <= remaining[position-1].GetSortKey()
	}

	return false
}

// generateRebalanceItems 映射全量重排结果
// Rebalance 生成全量重平衡的批量更新方案
func (s *Sorter[E, T]) Rebalance(elems []E) []T {
	return slice.Map(elems, func(idx int, src E) T {
		return s.convertFunc(src, idx)
	})
}

// RebalanceHierarchical 递归地对层级结构进行全量重平衡分配
// childrenFn: 获取子元素切片的函数，开启递归同步逻辑
func (s *Sorter[E, T]) RebalanceHierarchical(elems []E, childrenFn func(E) []E) {
	if len(elems) == 0 {
		return
	}

	// 处理当前层级
	s.Rebalance(elems)

	// 递归处理子层级
	for _, e := range elems {
		children := childrenFn(e)
		if len(children) > 0 {
			s.RebalanceHierarchical(children, childrenFn)
		}
	}
}

// SortBySortKey 通用排序辅助函数
func SortBySortKey[E Sortable](elems []E) {
	slices.SortFunc(elems, func(a, b E) int {
		if a.GetSortKey() < b.GetSortKey() {
			return -1
		}
		if a.GetSortKey() > b.GetSortKey() {
			return 1
		}
		return 0
	})
}
