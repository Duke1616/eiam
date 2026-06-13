package group

type CreateGroupRequest struct {
	Name string `json:"name" binding:"required"`
	Code string `json:"code" binding:"required"`
	Desc string `json:"desc"`
}

type UpdateGroupRequest struct {
	ID   int64  `json:"id" binding:"required"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type ListGroupRequest struct {
	Offset int64 `json:"offset"`
	Limit  int64 `json:"limit"`
}

type ListAttachedUserGroupsRequest struct {
	Username string `json:"username"`
	UserID   int64  `json:"user_id"`
	Offset   int64  `json:"offset"`
	Limit    int64  `json:"limit"`
	Keyword  string `json:"keyword"`
}

type ListAttachedRoleGroupsRequest struct {
	RoleCode string `json:"role_code" binding:"required"`
	Offset   int64  `json:"offset"`
	Limit    int64  `json:"limit"`
	Keyword  string `json:"keyword"`
}

type AssignMembersRequest struct {
	GroupCode string   `json:"group_code" binding:"required"`
	Usernames []string `json:"usernames" binding:"required"`
}

type RemoveMembersRequest struct {
	GroupCode string   `json:"group_code" binding:"required"`
	Usernames []string `json:"usernames" binding:"required"`
}

type ListMembersRequest struct {
	GroupCode string `json:"group_code" binding:"required"`
	Offset    int64  `json:"offset"`
	Limit     int64  `json:"limit"`
	Keyword   string `json:"keyword"`
}

type AssignRoleRequest struct {
	GroupCode string `json:"group_code" binding:"required"`
	RoleCode  string `json:"role_code" binding:"required"`
}

type RemoveRoleRequest struct {
	GroupCode string `json:"group_code" binding:"required"`
	RoleCode  string `json:"role_code" binding:"required"`
}

type Group struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Code  string `json:"code"`
	Desc  string `json:"desc"`
	Ctime int64  `json:"ctime"`
	Utime int64  `json:"utime"`
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
}

type ListGroupsResponse struct {
	Total  int64   `json:"total"`
	Groups []Group `json:"groups"`
}

type ListMembersResponse struct {
	Total   int64  `json:"total"`
	Members []User `json:"members"`
}

type Role struct {
	ID    int64  `json:"id"`
	Code  string `json:"code"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Ctime int64  `json:"ctime"`
	Utime int64  `json:"utime"`
}
