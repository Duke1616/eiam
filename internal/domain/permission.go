package domain

import (
	"strings"
	"time"
)

// ResourceType 资源类型标识
type ResourceType string

func (r ResourceType) String() string {
	return string(r)
}

const (
	ResourceTypeMenu ResourceType = "menu"
	ResourceTypeAPI  ResourceType = "api"
)

const (
	PrefixUser   = "user:"
	PrefixRole   = "role:"
	PrefixPolicy = "policy:"
)

const (
	SubjectTypeUser   = "user"
	SubjectTypeRole   = "role"
	SubjectTypePolicy = "policy"
)

func UserSubject(username string) string {
	return PrefixUser + username
}

func RoleSubject(code string) string {
	return PrefixRole + code
}

func PolicySubject(code string) string {
	return PrefixPolicy + code
}

// Subject 权限主体解析结果
type Subject struct {
	Type string // user, role, policy
	ID   string
}

// ParseSubject 统一解析马甲标识
func ParseSubject(s string) Subject {
	if strings.HasPrefix(s, PrefixUser) {
		return Subject{Type: SubjectTypeUser, ID: strings.TrimPrefix(s, PrefixUser)}
	}
	if strings.HasPrefix(s, PrefixRole) {
		return Subject{Type: SubjectTypeRole, ID: strings.TrimPrefix(s, PrefixRole)}
	}
	if strings.HasPrefix(s, PrefixPolicy) {
		return Subject{Type: SubjectTypePolicy, ID: strings.TrimPrefix(s, PrefixPolicy)}
	}
	return Subject{Type: "unknown", ID: s}
}

// Permission 权限项定义 (逻辑能力包)
// 这是一个全局概念，用于将多个物理资源 (API/Menu) 聚合为一个逻辑能力标识 (Code)
type Permission struct {
	ID      int64    `json:"id"`
	Service string   `json:"service"` // 所属服务标识：如 "iam"
	Code    string   `json:"code"`    // 逻辑唯一标识：如 "iam:user:view"
	Name    string   `json:"name"`    // 显示名：如 "查看用户"
	Group   string   `json:"group"`   // 所属分组：如 "用户管理"
	Needs   []string `json:"needs"`   // 依赖能力项

	// Bindings 权限项包含的物理资源映射 (全局通用，不分租户)
	Bindings []ResourceBinding `json:"bindings"`

	Ctime int64 `json:"ctime"`
	Utime int64 `json:"utime"`
}

// PermissionTree 领域级别的权限树
type PermissionTree struct {
	Service string
	Groups  []PermissionGroup
}

type PermissionGroup struct {
	Name    string
	Actions []Permission
}

// PermissionManifest 权限清单 (领域对象)
type PermissionManifest struct {
	Permissions []Permission
	Services    []ServiceNode
}

type ServiceNode struct {
	Code   string
	Name   string
	Groups []GroupNode
}

type GroupNode struct {
	Name    string
	Actions []string // 存储动作 Code
}

// ResourceBinding 物理资源绑定关系 (抽取租户 ID 为独立字段)
type ResourceBinding struct {
	TenantId    int64  `json:"tenant_id"`    // 租户标识，全局资产固定为 0
	ResourceURN string `json:"resource_urn"` // 统一资产标识，如 eiam:iam:menu:user
}

// PermissionProvider 定义了逻辑权限能力项的供应接口
// 用于实现模块化资产自声明 (Solution B: Handler-Based Self-Registration)
type PermissionProvider interface {
	ProvidePermissions() []Permission
}

// Authorization 授权信息详情（用于列表展示）
type Authorization struct {
	ID          int64     `json:"id"`
	Subject     Subject   `json:"subject"`      // 授权主体 (user:xxx 或 role:xxx)
	Target      Subject   `json:"target"`       // 权限目标 (policy:xxx 或 role:xxx)
	SubjectName string    `json:"subject_name"` // 主体展示虚名（如：张三）
	TargetName  string    `json:"target_name"`  // 目标展示虚名（如：管理员策略）
	Note        string    `json:"note"`         // 备注
	Scope       string    `json:"scope"`        // 资源范围
	Ctime       time.Time `json:"ctime"`        // 授权时间
}

type AuthorizationQuery struct {
	PageSize int64
	PageNum  int64
	Subject  string // 筛选主体
	Target   string // 筛选目标
}
