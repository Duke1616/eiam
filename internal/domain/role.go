package domain

const (
	RoleTypeSystem uint8 = 1 // 系统预设全局角色 (tenant_id 强制为 0)
	RoleTypeCustom uint8 = 2 // 租户私有自定义角色
)

// Role 角色定义集：既是策略容器，也是可扮演身份（Principal）
type Role struct {
	ID       int64  // ID
	TenantID int64  // 0 表示系统全局角色，>0 表示租户自定义角色
	Code     string // code 标识码，如 "AdminRole"
	Name     string // 角色显示名称
	Desc     string // 描述
	Type     uint8  // 角色类型: 1-系统预设, 2-租户自定义

	// InlinePolicies 内联权限策略：该角色特有的权限声明
	InlinePolicies []Policy

	// ManagedPolicies 托管策略：引用全局定义的独立策略实体
	ManagedPolicies []Policy

	// AssumeRolePolicy 信任策略文档：定义“谁能扮演该角色”
	AssumeRolePolicy Policy
}
