package domain

// Department 部门领域模型
type Department struct {
	ID         int64    `json:"id"`
	ParentID   int64    `json:"parent_id"`
	Name       string   `json:"name"`
	Sort       int64    `json:"sort"`
	Leaders    []string `json:"leaders"`
	MainLeader string   `json:"main_leader"`
	Ctime      int64    `json:"ctime"`
	Utime      int64    `json:"utime"`
}

// DepartmentTree 部门树
type DepartmentTree []*DepartmentNode

// DepartmentNode 部门树节点
type DepartmentNode struct {
	Department
	Children []*DepartmentNode `json:"children,omitempty"`
}
