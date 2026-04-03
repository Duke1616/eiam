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
	ID     int64  `json:"id"`
	Code   string `json:"code"`   // 逻辑唯一标识：如 "iam:user:view"
	Name   string `json:"name"`   // 显示名：如 "查看用户"
	Desc   string `json:"desc"`   // 描述信息
	Group  string `json:"group"`  // 所属分组：如 "用户管理"
	Status int32  `json:"status"` // 状态：1-启用, 0-禁用

	// Bindings 权限项包含的物理资源映射 (全局通用，不分租户)
	Bindings []ResourceBinding `json:"bindings"`

	Ctime int64 `json:"ctime"`
	Utime int64 `json:"utime"`
}

// ResourceBinding 物理资源绑定关系 (不涉及租户，仅表达“能力由哪些物理资产构成”)
type ResourceBinding struct {
	ResourceType ResourceType `json:"resource_type"`
	ResourceID   int64        `json:"resource_id"`
}
