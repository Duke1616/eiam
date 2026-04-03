package permission

import "github.com/Duke1616/eiam/internal/domain"

type CreatePermissionRequest struct {
	Code string `json:"code" binding:"required"`
	Desc string `json:"desc"`
}

type BindResourcesRequest struct {
	PermID   int64               `json:"perm_id" binding:"required"`
	PermCode string              `json:"perm_code" binding:"required"`
	ResType  domain.ResourceType `json:"res_type" binding:"required"`
	ResIDs   []int64             `json:"res_ids" binding:"required"`
}

type AssignRoleRequest struct {
	UserID   int64  `json:"user_id" binding:"required"`
	RoleCode string `json:"role_code" binding:"required"`
}
