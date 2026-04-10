package domain

// PolicyType 策略类型：系统(托管) 或 用户(自定义)
type PolicyType int

const (
	SystemPolicy PolicyType = 1
	CustomPolicy PolicyType = 2
)

// Effect 策略效果
type Effect string

const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Policy 权限策略实体：这才是真正的核心权限对象
type Policy struct {
	ID        int64
	TenantID  int64       // 0 表示系统全局策略
	Name      string      // 策略名称
	Code      string      // 策略唯一标识码
	Desc      string      // 描述
	Type      PolicyType  // 系统或用户自定义
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// RolePolicyRelation 描述角色与策略的绑定关系详情
type RolePolicyRelation struct {
	RoleCode string
	PolyCode string
}

// Statement 权限语句：定义 Action, Resource 和 Condition
type Statement struct {
	Effect    Effect         `json:"Effect"`
	Action    []string       `json:"Action"`
	Resource  []string       `json:"Resource"` // 这里应填入 URN 字符串
	Condition map[string]any `json:"Condition,omitempty"`
}
