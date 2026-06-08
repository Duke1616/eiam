package department

type CreateDeptRequest struct {
	ParentID   int64    `json:"parent_id"`
	Name       string   `json:"name" binding:"required"`
	Sort       int64    `json:"sort"`
	Leaders    []string `json:"leaders"`
	MainLeader string   `json:"main_leader"`
}

type UpdateDeptRequest struct {
	ID         int64    `json:"id" binding:"required"`
	ParentID   int64    `json:"parent_id"`
	Name       string   `json:"name" binding:"required"`
	Sort       int64    `json:"sort"`
	Leaders    []string `json:"leaders"`
	MainLeader string   `json:"main_leader"`
}

type AssignUsersRequest struct {
	DeptID  int64   `json:"dept_id" binding:"required"`
	UserIDs []int64 `json:"user_ids" binding:"required"`
}

type RemoveUsersRequest struct {
	DeptID  int64   `json:"dept_id" binding:"required"`
	UserIDs []int64 `json:"user_ids" binding:"required"`
}

type ListMembersRequest struct {
	DeptID  int64  `json:"dept_id" binding:"required"`
	Offset  int64  `json:"offset"`
	Limit   int64  `json:"limit"`
	Keyword string `json:"keyword"`
}

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

type DepartmentNode struct {
	Department
	Children []*DepartmentNode `json:"children,omitempty"`
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
}

type ListMembersResponse struct {
	Total   int64  `json:"total"`
	Members []User `json:"members"`
}
