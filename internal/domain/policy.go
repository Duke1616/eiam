package domain

import (
	"database/sql/driver"
	"errors"
	"slices"
	"strings"
)

var (
	ErrDuplicatePolicyCode = errors.New("策略标识码已存在，请更换后重试或避免与系统预置策略冲突")
)

// ===========================================================================
// 基础枚举
// ===========================================================================

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

// AccessLevel 访问级别
type AccessLevel string

const (
	AccessLevelAll     AccessLevel = "ALL"
	AccessLevelPartial AccessLevel = "PARTIAL"
)

// ===========================================================================
// Condition（值对象）
// ===========================================================================

// Condition 策略触发条件：基于 Operator 的结构化判定
type Condition struct {
	Operator string `json:"Operator"` // 匹配操作符：StringEquals, NumericGreater 等
	Key      string `json:"Key"`      // 匹配关键字：iam:UserId, sdk:ClientIp 等
	Value    any    `json:"Value"`    // 匹配目标值：可以是单个值或数组
}

// ===========================================================================
// Statement（值对象 + 行为）
// ===========================================================================

// Statement 权限语句：定义 Action, Resource 和 Condition
type Statement struct {
	Effect    Effect      `json:"Effect"`
	Action    []string    `json:"Action"`
	Resource  []string    `json:"Resource"` // 这里应填入 URN 字符串
	Condition []Condition `json:"Condition,omitempty"`
}

// MatchesAction 判断该语句的 Action 模式是否命中指定权限码
// 支持精确匹配（iam:user:view）和通配符匹配（iam:user:*）
func (s Statement) MatchesAction(code string) bool {
	return slices.ContainsFunc(s.Action, func(pattern string) bool {
		if pattern == code {
			return true
		}
		return strings.HasSuffix(pattern, "*") &&
			strings.HasPrefix(code, strings.TrimSuffix(pattern, "*"))
	})
}

// ContainsServiceAction 检查语句中是否存在属于指定服务的操作
func (s Statement) ContainsServiceAction(serviceCode string) bool {
	return slices.ContainsFunc(s.Action, func(act string) bool {
		return strings.HasPrefix(act, serviceCode)
	})
}

// IsGlobalResource 判断该语句是否为全局资源授权（Resource = ["*"]）
func (s Statement) IsGlobalResource() bool {
	return len(s.Resource) == 1 && s.Resource[0] == "*"
}

// ===========================================================================
// Policy（聚合根 + 行为）
// ===========================================================================

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

// CollectActions 从所有语句中提取 Action 列表（含通配符，未去重）
func (p Policy) CollectActions() []string {
	var actions []string
	for _, stmt := range p.Statement {
		actions = append(actions, stmt.Action...)
	}
	return actions
}

// FindGrantingStatement 查找第一条授予指定权限码的 Allow 语句
// 用于反向追溯该权限点的资源范围与生效条件
func (p Policy) FindGrantingStatement(code string) (Statement, bool) {
	for _, stmt := range p.Statement {
		if stmt.Effect == Allow && stmt.MatchesAction(code) {
			return stmt, true
		}
	}
	return Statement{}, false
}

// FindApplicableStatement 查找第一条命中的语句，遵循 Deny 优先原则
func (p Policy) FindApplicableStatement(code string) (Statement, bool) {
	// 优先查找拒绝语句 (Deny 优先级最高)
	for _, stmt := range p.Statement {
		if stmt.Effect == Deny && stmt.MatchesAction(code) {
			return stmt, true
		}
	}

	// 其次查找允许语句
	for _, stmt := range p.Statement {
		if stmt.Effect == Allow && stmt.MatchesAction(code) {
			return stmt, true
		}
	}

	return Statement{}, false
}

// ResolveResourceScope 判定策略对指定服务的资源作用域
// 返回 "*" 表示全局资源，"SPECIFIC" 表示限定资源
func (p Policy) ResolveResourceScope(serviceCode string) string {
	for _, stmt := range p.Statement {
		if stmt.ContainsServiceAction(serviceCode) && stmt.IsGlobalResource() {
			return "*"
		}
	}
	return "SPECIFIC"
}

// ===========================================================================
// 摘要展示模型（只读，专为 API 输出设计）
// ===========================================================================

// PolicySummary 策略详情摘要
type PolicySummary struct {
	Policy   Policy
	Services []PolicyServiceSummary
}

// PolicyServiceSummary 策略在特定服务下的表现
type PolicyServiceSummary struct {
	ServiceCode   string
	ServiceName   string
	Effect        Effect
	Level         AccessLevel
	GrantedCount  int
	TotalCount    int
	ResourceScope string
	Conditions    []Condition
	Actions       []GrantedAction
}

// GrantedAction 策略授予的最小粒度操作（含边界条件）
type GrantedAction struct {
	Code      string
	Name      string
	Group     string
	Effect    Effect
	Resource  []string
	Condition []Condition
}

// BatchResult 批量操作返回结果统计
type BatchResult struct {
	Total    int64 // 预期处理总数
	Inserted int64 // 实际新插入的数量
	Ignored  int64 // 因冲突被忽略的数量
}
