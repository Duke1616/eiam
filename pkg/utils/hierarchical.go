package utils

// HierarchicalAction 定义层级走访逻辑
type HierarchicalAction[T any] func(node T, parent T)

// WalkHierarchical 泛型层级走访器。
func WalkHierarchical[T any](nodes []T, getChildren func(T) []T, action HierarchicalAction[T]) {
	var zero T
	walkHierarchical(nodes, zero, getChildren, action)
}

func walkHierarchical[T any](nodes []T, parent T, getChildren func(T) []T, action HierarchicalAction[T]) {
	for i := range nodes {
		action(nodes[i], parent)
		children := getChildren(nodes[i])
		if len(children) > 0 {
			walkHierarchical[T](children, nodes[i], getChildren, action)
		}
	}
}
