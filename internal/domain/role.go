package domain

// Role 角色定义
type Role struct {
	ID       int64    // ID
	TenantID int64    // 0 表示系统全局角色，>0 表示租户自定义角色
	Code     string   // code 标识
	Name     string   // 名称
	Desc     string   // 详情
	Status   bool     // 状态
	Policies []Policy // 绑定的权限策略列表
}

// Effect 策略效果
type Effect string

const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Policy 权限策略文档
type Policy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement 权限语句
type Statement struct {
	Effect    Effect         `json:"Effect"`
	Action    []string       `json:"Action"`
	Resource  []string       `json:"Resource"`
	Condition map[string]any `json:"Condition,omitempty"`
}
