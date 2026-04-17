package role

type CreateRoleRequest struct {
	Name string `json:"name" binding:"required"`
	Code string `json:"code" binding:"required"`
	Desc string `json:"desc"`
}

type UpdateRoleRequest struct {
	ID   int64  `json:"id" binding:"required"`
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
	ID             int64    `json:"id"`
	Code           string   `json:"code"`
	Name           string   `json:"name"`
	Desc           string   `json:"desc"`
	Type           uint8    `json:"type"`
	InlinePolicies []Policy `json:"inline_policies"`
}

type Policy struct {
	Name      string      `json:"name"`
	Code      string      `json:"code"`
	Statement []Statement `json:"statement"`
}

type Statement struct {
	Effect   string   `json:"effect"`
	Action   []string `json:"action"`
	Resource []string `json:"resource"`
}

type RetrieveRole struct {
	Total int64  `json:"total"`
	Roles []Role `json:"roles"`
}
