package domain

// Permission 权限项定义 (逻辑能力包)
type Permission struct {
	ID       int64               `json:"id"`
	TenantID int64               `json:"tenant_id"` // 0 表示系统全局权限，>0 表示租户独有权限
	Code     string              `json:"code"`      // 逻辑唯一标识：iam:user:view
	Name     string              `json:"name"`      // 显示名：如 "查看用户"
	Desc     string              `json:"desc"`      // 描述信息
	Group    string              `json:"group"`     // 权限分组：如 "用户管理"
	Status   bool                `json:"status"`    // 是否启用
	Bindings []PermissionBinding `json:"bindings"`  // 对应的资源绑定列表
	Ctime    int64               `json:"ctime"`
	Utime    int64               `json:"utime"`
}

// ResourceType 资源类型定义
type ResourceType string

const (
	ResAPI    ResourceType = "API"
	ResMenu   ResourceType = "MENU"
)

// PermissionBinding 权限与资源的关联关系 (M:N 映射层)
type PermissionBinding struct {
	ID           int64        `json:"id"`
	TenantID     int64        `json:"tenant_id"` // 支持租户级别的差异化绑定
	PermID       int64        `json:"perm_id"`   // 关联 Permission.ID
	PermCode     string       `json:"perm_code"` // 记录 Code 方便关联查询
	ResourceType ResourceType `json:"resource_type"`
	ResourceID   int64        `json:"resource_id"` // 物理资源 ID (API_ID, Menu_ID, etc.)
}
