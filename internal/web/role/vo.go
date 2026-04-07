package role

type CreateRoleRequest struct {
	Name string `json:"name" binding:"required"`
	Code string `json:"code" binding:"required"`
	Desc string `json:"desc"`
}

type UpdateRoleRequest struct {
	Name string `json:"name"`
	Code string `json:"code" binding:"required"`
	Desc string `json:"desc"`
}

type ListRoleRequest struct {
	Offset int64 `json:"offset"`
	Limit  int64 `json:"limit"`
}

type AssignRoleRequest struct {
	RoleCode string `json:"role_code" binding:"required"`
}

type Role struct {
	ID   int64  `json:"id"`
	Code string `json:"code"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type RetrieveRole struct {
	Total int64  `json:"total"`
	Roles []Role `json:"roles"`
}
