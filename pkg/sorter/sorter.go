package sorter

import (
	"slices"

	"github.com/samber/lo"
)

const (
	// DefaultIndexGap 默认稀疏索引间隔
	DefaultIndexGap = 1000
)

// Sortable 可排序元素接口
type Sortable interface {
	GetID() int64
	GetSortKey() int64
}

// Item 排序更新项
type Item struct {
	ID      int64
	SortKey int64
}

// ReorderPlan 重排计算方案
type ReorderPlan struct {
	// Unchanged 是否未发生位置变化（原地拖拽，无需写库）
	Unchanged bool
	// NeedRebalance 是否需要全局重平衡
	NeedRebalance bool
	// NewSortKey 单条更新时的目标 SortKey（快速路径）
	NewSortKey int64
	// Items 批量重平衡更新项列表（慢路径）
	Items []Item
}

// Reorder 使用默认步长计算重排方案
func Reorder[E Sortable](elements []E, draggedID, targetPosition int64) ReorderPlan {
	return ReorderWithGap(elements, draggedID, targetPosition, DefaultIndexGap)
}

// ReorderWithGap 自定义稀疏步长计算重排方案
func ReorderWithGap[E Sortable](elements []E, draggedID, targetPosition, gap int64) ReorderPlan {
	if gap <= 0 {
		gap = DefaultIndexGap
	}

	// 1. 查找被拖拽元素在当前列表中的位置
	oldIdx := slices.IndexFunc(elements, func(e E) bool {
		return e.GetID() == draggedID
	})

	// 2. 原地拖拽识别：同列表且位置未变，直接短路（零数据库写开销）
	if oldIdx != -1 && int64(oldIdx) == targetPosition {
		return ReorderPlan{
			Unchanged:     true,
			NeedRebalance: false,
			NewSortKey:    elements[oldIdx].GetSortKey(),
		}
	}

	// 3. 构建移除被拖拽元素后的剩余列表
	remaining := removeByID(elements, draggedID)

	// 4. 规范化 targetPosition 边界 [0, len(remaining)]
	n := int64(len(remaining))
	if targetPosition < 0 {
		targetPosition = 0
	}
	if targetPosition > n {
		targetPosition = n
	}

	// 5. 计算目标位置的新 SortKey
	newSortKey := calculateSortKey(remaining, targetPosition, gap)

	// 6. 检测是否需要重平衡（空间耗尽、衰减至0或逆序冲突）
	if needsRebalance(remaining, targetPosition, newSortKey) {
		finalIDs := lo.Map(remaining, func(e E, _ int) int64 {
			return e.GetID()
		})
		finalIDs = slices.Insert(finalIDs, int(targetPosition), draggedID)

		// 批量按均匀步长分配新的 SortKey
		items := lo.Map(finalIDs, func(id int64, idx int) Item {
			return Item{
				ID:      id,
				SortKey: int64(idx+1) * gap,
			}
		})

		return ReorderPlan{
			Unchanged:     false,
			NeedRebalance: true,
			Items:         items,
		}
	}

	// 快速路径：仅需单条更新
	return ReorderPlan{
		Unchanged:     false,
		NeedRebalance: false,
		NewSortKey:    newSortKey,
	}
}

// removeByID 过滤掉指定 ID 的元素
func removeByID[E Sortable](elems []E, id int64) []E {
	return lo.Filter(elems, func(e E, _ int) bool {
		return e.GetID() != id
	})
}

// calculateSortKey 计算插入点的新 SortKey
func calculateSortKey[E Sortable](elems []E, position, gap int64) int64 {
	n := int64(len(elems))

	// 列表为空或追加至末尾
	if n == 0 || position >= n {
		if n == 0 {
			return gap
		}
		return elems[n-1].GetSortKey() + gap
	}

	// 插入至首位
	if position == 0 {
		return elems[0].GetSortKey() / 2
	}

	// 插入至中间
	return (elems[position-1].GetSortKey() + elems[position].GetSortKey()) / 2
}

// needsRebalance 检查是否空间不足触发重平衡
func needsRebalance[E Sortable](elems []E, position, newSortKey int64) bool {
	n := int64(len(elems))
	if n == 0 {
		return false
	}

	// 头部插入：key 衰减至 <= 0 或未能严格小于后继元素
	if position == 0 {
		return newSortKey <= 0 || newSortKey >= elems[0].GetSortKey()
	}

	// 中间插入：key 未能严格落入 (prev, next) 严格递增区间
	if position < n {
		return newSortKey <= elems[position-1].GetSortKey() || newSortKey >= elems[position].GetSortKey()
	}

	// 尾部插入：防溢出或历史脏数据逆序冲突
	return newSortKey <= elems[n-1].GetSortKey()
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

// RebalanceHierarchical 递归对多层级嵌套结构进行均匀稀疏重平衡分配
func RebalanceHierarchical[E any](elems []E, childrenFn func(E) []E, assignFn func(elem E, sortKey int64), gap ...int64) {
	step := int64(DefaultIndexGap)
	if len(gap) > 0 && gap[0] > 0 {
		step = gap[0]
	}
	rebalanceHierarchical(elems, childrenFn, assignFn, step)
}

func rebalanceHierarchical[E any](elems []E, childrenFn func(E) []E, assignFn func(elem E, sortKey int64), gap int64) {
	for i, elem := range elems {
		assignFn(elem, int64(i+1)*gap)
		children := childrenFn(elem)
		if len(children) > 0 {
			rebalanceHierarchical(children, childrenFn, assignFn, gap)
		}
	}
}
