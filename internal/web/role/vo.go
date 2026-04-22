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
	Offset  int64  `json:"offset"`
	Limit   int64  `json:"limit"`
	Keyword string `json:"keyword"`
}

type ListUserRolesRequest struct {
	UserID  int64  `json:"user_id"`
	Offset  int64  `json:"offset"`
	Limit   int64  `json:"limit"`
	Keyword string `json:"keyword"`
}

type AssignRoleRequest struct {
	RoleCode string `json:"role_code" binding:"required"`
}

type BatchAssignRoleRequest struct {
	Usernames []string `json:"usernames" binding:"required"`
	RoleCode  string   `json:"role_code" binding:"required"`
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
	Name      string           `json:"name"`
	Code      string           `json:"code"`
	Statement []Statement      `json:"statement"`
	Services  []ServiceSummary `json:"services,omitempty"`
}

type Statement struct {
	Effect    string      `json:"effect"`
	Action    []string    `json:"action"`
	Resource  []string    `json:"resource"`
	Condition []Condition `json:"condition,omitempty"`
}

type Condition struct {
	Operator string `json:"operator"`
	Key      string `json:"key"`
	Value    any    `json:"value"`
}

type ServiceSummary struct {
	ServiceCode   string         `json:"service_code"`
	ServiceName   string         `json:"service_name"`
	Effect        string         `json:"effect"`
	Level         string         `json:"level"`
	GrantedCount  int            `json:"granted_count"`
	TotalCount    int            `json:"total_count"`
	ResourceScope string         `json:"resource_scope"`
	Condition     string         `json:"condition"`
	Actions       []ActionDetail `json:"actions"`
}

type ActionDetail struct {
	Code      string `json:"action"`
	Name      string `json:"name"`
	Group     string `json:"group"`
	Resource  string `json:"resource"`  // 转换为易读格式的字符串
	Condition string `json:"condition"` // 转换为易读格式的字符串
}

type RetrieveRole struct {
	Total int64  `json:"total"`
	Roles []Role `json:"roles"`
}

type RoleAnalysisReq struct {
	RoleCode string `json:"role_code" binding:"required"`
}

type RoleAnalysisRes struct {
	InlinePolicies []Policy `json:"inline_policies"`
}

type RoleInheritanceReq struct {
	RoleCode       string `json:"role_code" binding:"required"`
	ParentRoleCode string `json:"parent_role_code" binding:"required"`
}

type RoleInheritanceInfo struct {
	Code        string `json:"code"`
	IsDirect    bool   `json:"is_direct"`    // 是否为直接继承 (第一层)
	IsImmutable bool   `json:"is_immutable"` // 是否不可变 (不允许手动移除)
}

type GetParentRolesReq struct {
	RoleCode string `json:"role_code" binding:"required"`
}
