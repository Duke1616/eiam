package domain

// Role 角色定义集：既是策略容器，也是可扮演身份（Principal）
type Role struct {
	ID       int64  // ID
	TenantID int64  // 0 表示系统全局角色，>0 表示租户自定义角色
	Code     string // code 标识码，如 "AdminRole"
	Name     string // 角色显示名称
	Desc     string // 描述
	Status   bool   // 状态

	// Policies 权限策略文档：该角色“能干什么”
	Policies []Policy

	// AssumeRolePolicy 信任策略文档：定义“谁能扮演该角色”
	// 这是阿里云 RAM 跨账号/跨服务授权的精髓。
	// 这里存的是一个策略 JSON。
	AssumeRolePolicy Policy
}
