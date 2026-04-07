package permission

type CreatePermissionRequest struct {
	Code string `json:"code" binding:"required"`
	Desc string `json:"desc"`
}

type BindResourcesRequest struct {
	PermID   int64    `json:"perm_id" binding:"required"`
	PermCode string   `json:"perm_code" binding:"required"`
	ResURNs  []string `json:"res_urns" binding:"required"`
}

type AssignRoleRequest struct {
	UserID   int64  `json:"user_id" binding:"required"`
	RoleCode string `json:"role_code" binding:"required"`
}
