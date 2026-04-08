package domain

// ResourceType 资源类型标识
type ResourceType string

func (r ResourceType) String() string {
	return string(r)
}

const (
	ResourceTypeMenu ResourceType = "menu"
	ResourceTypeAPI  ResourceType = "api"
)

// Permission 权限项定义 (逻辑能力包)
// 这是一个全局概念，用于将多个物理资源 (API/Menu) 聚合为一个逻辑能力标识 (Code)
type Permission struct {
	ID      int64  `json:"id"`
	Service string `json:"service"` // 所属服务标识：如 "iam"
	Code    string `json:"code"`    // 逻辑唯一标识：如 "iam:user:view"
	Name    string `json:"name"`    // 显示名：如 "查看用户"
	Group   string `json:"group"`   // 所属分组：如 "用户管理"

	// Bindings 权限项包含的物理资源映射 (全局通用，不分租户)
	Bindings []ResourceBinding `json:"bindings"`

	Ctime int64 `json:"ctime"`
	Utime int64 `json:"utime"`
}

// ResourceBinding 物理资源绑定关系 (抽取租户 ID 为独立字段)
type ResourceBinding struct {
	TenantID    string `json:"tenant_id"`    // 租户标识，全局资产固定为 "0"
	ResourceURN string `json:"resource_urn"` // 统一资产标识，如 eiam:iam:menu:user
}

// PermissionProvider 定义了逻辑权限能力项的供应接口
// 用于实现模块化资产自声明 (Solution B: Handler-Based Self-Registration)
type PermissionProvider interface {
	ProvidePermissions() []Permission
}
