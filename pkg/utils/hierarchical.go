package utils

// WalkHierarchical 泛型层级走访器。
// T: 节点类型 (如 *domain.Menu)
// nodes: 待处理的起始切片
// getChildren: 告诉函数如何获取当前节点的子节点集合
// action: 对当前遍历到的单个节点执行的逻辑
func WalkHierarchical[T any](nodes []T, getChildren func(T) []T, action func(T)) {
	for _, n := range nodes {
		// 1. 执行当前节点的业务操作
		action(n)

		// 2. 递归拉取子节点处理
		children := getChildren(n)
		if len(children) > 0 {
			WalkHierarchical[T](children, getChildren, action)
		}
	}
}
