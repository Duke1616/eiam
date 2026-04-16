package domain

import (
	"database/sql/driver"
)

// PolicyType 策略类型：系统(托管) 或 用户(自定义)
type PolicyType uint8

func (p PolicyType) Value() (driver.Value, error) {
	return int64(p), nil
}

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
	ID              int64
	TenantID        int64       // 0 表示系统全局策略
	Name            string      // 策略名称
	Code            string      // 策略唯一标识码
	Desc            string      // 描述
	Type            PolicyType  // 系统或用户自定义
	Version         string      `json:"Version"`
	Statement       []Statement `json:"Statement"`
	Ctime           int64
	AssignmentCount int64 // 关联授权数量
}

// Statement 权限语句：定义 Action, Resource 和 Condition
type Statement struct {
	Effect    Effect      `json:"Effect"`
	Action    []string    `json:"Action"`
	Resource  []string    `json:"Resource"` // 这里应填入 URN 字符串
	Condition []Condition `json:"Condition,omitempty"`
}

// Condition 策略触发条件：基于 Operator 的结构化判定
type Condition struct {
	Operator string `json:"Operator"` // 匹配操作符：StringEquals, NumericGreater 等
	Key      string `json:"Key"`      // 匹配关键字：iam:UserId, sdk:ClientIp 等
	Value    any    `json:"Value"`    // 匹配目标值：可以是单个值或数组
}

// BatchResult 批量操作返回结果统计
type BatchResult struct {
	Total    int64 // 预期处理总数
	Inserted int64 // 实际新插入的数量
	Ignored  int64 // 因冲突被忽略的数量
}
