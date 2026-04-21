package domain

import (
	"fmt"
	"strings"

	"github.com/samber/lo"
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
	PrefixUser = "user:"
	PrefixRole = "role:"
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

// Subject 权限主体解析结果
type Subject struct {
	Type string // user, role, policy
	ID   string
	Name string // 展示名称
	Desc string // 描述
}

// ParseSubject 统一解析马甲标识
func ParseSubject(s string) Subject {
	if strings.HasPrefix(s, PrefixUser) {
		return Subject{Type: SubjectTypeUser, ID: strings.TrimPrefix(s, PrefixUser)}
	}
	if strings.HasPrefix(s, PrefixRole) {
		return Subject{Type: SubjectTypeRole, ID: strings.TrimPrefix(s, PrefixRole)}
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
	Desc    string   `json:"desc"`    // 业务描述信息
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
	TenantId    int64  `json:"tenant_id"`    // 租户标识，全局资产固定为 1
	ResourceURN string `json:"resource_urn"` // 统一资产标识，如 eiam:iam:menu:user
}

// PermissionProvider 定义了逻辑权限能力项的供应接口
// 用于实现模块化资产自声明 (Solution B: Handler-Based Self-Registration)
type PermissionProvider interface {
	ProvidePermissions() []Permission
}

// Authorization 授权信息详情（用于列表展示）
type Authorization struct {
	ID          int64   `json:"id"`
	Subject     Subject `json:"subject"`      // 授权主体 (user:xxx 或 role:xxx)
	Target      Subject `json:"target"`       // 权限目标 (policy 或 role)
	SubjectName string  `json:"subject_name"` // 主体展示虚名（如：张三）
	TargetName  string  `json:"target_name"`  // 目标展示虚名（如：管理员策略）
	Note        string  `json:"note"`         // 备注
	Scope       string  `json:"scope"`        // 资源范围
	Ctime       int64   `json:"ctime"`        // 授权时间
}

// EntityMetadata 实体元数据（用于辅助展示）
type EntityMetadata struct {
	Name string
	Type uint8
	Desc string
}

// FormatGovernance 根据元数据格式化治理展示信息
func (a *Authorization) FormatGovernance(v0Meta, v1Meta EntityMetadata) {
	// 1. 处理主体名称：如果是角色展示 Code，否则回填名称或 ID
	if a.Subject.Type == SubjectTypeRole {
		a.SubjectName = a.Subject.ID
	} else {
		a.SubjectName = lo.Ternary(v0Meta.Name != "", v0Meta.Name, a.Subject.ID)
	}

	// 2. 处理目标名称：如果是角色展示 Code，否则回填名称或 ID
	if a.Target.Type == SubjectTypeRole {
		a.TargetName = a.Target.ID
	} else {
		a.TargetName = lo.Ternary(v1Meta.Name != "", v1Meta.Name, a.Target.ID)
	}

	// 3. 计算资源范围 Scope (如：系统策略、自定义角色)
	if v1Meta.Type > 0 {
		prefix := lo.Ternary(v1Meta.Type == 1, "系统", "自定义")
		kind := lo.Ternary(a.Target.Type == SubjectTypeRole, "角色", "策略")
		a.Scope = prefix + kind
	}

	// 4. 处理备注提示（动态生成描述语句）
	switch a.Target.Type {
	case SubjectTypeRole:
		switch a.Subject.Type {
		case SubjectTypeUser:
			a.Note = "直接授权"
		case SubjectTypeRole:
			a.Note = fmt.Sprintf("角色 %s 继承自角色 %s", a.SubjectName, a.TargetName)
		}
	case SubjectTypePolicy:
		a.Note = lo.Ternary(v1Meta.Desc != "", v1Meta.Desc, "权限授权")
	}
}

type AuthorizationSubType string
type AuthorizationObjType string

const (
	AuthSubUser AuthorizationSubType = "user"
	AuthSubRole AuthorizationSubType = "role"

	AuthObjRole         AuthorizationObjType = "role"
	AuthObjSystemPolicy AuthorizationObjType = "system_policy"
	AuthObjCustomPolicy AuthorizationObjType = "custom_policy"
)

// String 返回 AuthorizationSubType 的字符串表示
func (t AuthorizationSubType) String() string {
	return string(t)
}

// SubjectType 返回对应的 SubjectType
func (t AuthorizationSubType) SubjectType() string {
	switch t {
	case AuthSubUser:
		return SubjectTypeUser
	case AuthSubRole:
		return SubjectTypeRole
	default:
		return ""
	}
}

// Prefix 返回对应的前缀
func (t AuthorizationSubType) Prefix() string {
	switch t {
	case AuthSubUser:
		return PrefixUser
	case AuthSubRole:
		return PrefixRole
	default:
		return ""
	}
}

// String 返回 AuthorizationObjType 的字符串表示
func (t AuthorizationObjType) String() string {
	return string(t)
}

type AuthorizationQuery struct {
	Offset  int64
	Limit   int64
	Keyword string               // 模糊搜索关键字
	SubType AuthorizationSubType // 筛选主体类型 (用户/角色)
	ObjType AuthorizationObjType // 筛选目标类型 (角色/系统策略/自定义策略)
}
