package capability

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/Duke1616/eiam/pkg/pbac"
)

// 权限作用域常量
const (
	ScopeSystem = "system"
	ScopeTenant = "tenant"
)

// Model 业务领域模块元数据 (纯数据对象，无运行时副作用)
type Model struct {
	Service string `json:"service"` // 所属服务，如 "iam"
	Name    string `json:"name"`    // 领域模块名，如 "role"
	Group   string `json:"group"`   // 前端授权展示分组名称，如 "角色管理"
	Scope   string `json:"scope"`   // 默认生效作用域，"tenant" 或 "system"
}

// URN 返回模块唯一资源标识符，如 "iam:role"
func (m Model) URN() string {
	return m.Service + ":" + m.Name
}

// Permission 逻辑权限能力定义 (全平台统一治理标准)
type Permission struct {
	Service            string                   `json:"service"`
	Code               string                   `json:"code"`
	Name               string                   `json:"name"`
	Group              string                   `json:"group"`
	Needs              []string                 `json:"needs"`
	NoSync             bool                     `json:"no_sync"`
	NoAudit            bool                     `json:"no_audit"`
	Scope              string                   `json:"scope"`
	Sort               int                      `json:"sort"`
	AccessScopePresets []pbac.AccessScopePreset `json:"access_scope_presets,omitempty"`
}

// ResourceInfo 物理接口元数据 (运行时鉴权与资产上报载体)
type ResourceInfo struct {
	Name             string             `json:"name"`
	Method           string             `json:"method"`
	Path             string             `json:"path"`
	Code             string             `json:"code"`
	Needs            []string           `json:"needs"`
	Group            string             `json:"group"`
	Service          string             `json:"service"`
	NoAudit          bool               `json:"no_audit"`
	AllowCrossTenant bool               `json:"allow_cross_tenant"`
	FilterProfile    pbac.FilterProfile `json:"filter_profile,omitempty"`
}

// Menu 菜单资产模型
type Menu struct {
	Name           string   `json:"name"`
	Path           string   `json:"path"`
	ParentURN      string   `json:"parent_urn"`
	Component      string   `json:"component"`
	Redirect       string   `json:"redirect"`
	PermissionCode string   `json:"permission_code"`
	Sort           int64    `json:"sort"`
	Meta           MenuMeta `json:"meta"`
	Children       []Menu   `json:"children"`
}

type MenuMeta struct {
	Title       string   `json:"title"`
	Icon        string   `json:"icon"`
	IsHidden    bool     `json:"is_hidden"`
	IsAffix     bool     `json:"is_affix"`
	IsKeepAlive bool     `json:"is_keepalive"`
	Platforms   []string `json:"platforms"`
}

// PermissionProvider 逻辑权限提供者契约
type PermissionProvider interface {
	ProvidePermissions() []Permission
}

// MenuProvider 菜单资产提供者契约
type MenuProvider interface {
	ProvideMenus() []Menu
}

// SyncRequest 定义了资产上报的标准快照模型 (Snapshot)
type SyncRequest struct {
	Source      string         `json:"source,omitempty"`
	Service     string         `json:"service"`
	Permissions []Permission   `json:"permissions"`
	APIs        []ResourceInfo `json:"apis"`
	Menus       []Menu         `json:"menus"`
}

func (r SyncRequest) OwnerKey() string {
	if r.Source == "" {
		return r.Service
	}
	return r.Service + "@" + r.Source
}

// Hash 计算资产快照的稳定哈希值
func (r *SyncRequest) Hash() string {
	r.normalize()
	b, _ := json.Marshal(r)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// normalize 对请求体内的所有资产进行确定性排序，保证序列化结果稳定
func (r *SyncRequest) normalize() {
	slices.SortFunc(r.Permissions, func(a, b Permission) int { return cmp.Compare(a.Code, b.Code) })
	slices.SortFunc(r.APIs, func(a, b ResourceInfo) int {
		if r := cmp.Compare(a.Path, b.Path); r != 0 {
			return r
		}
		return cmp.Compare(a.Method, b.Method)
	})
	slices.SortFunc(r.Menus, func(a, b Menu) int { return cmp.Compare(a.Name, b.Name) })
}

// Reporter 资产上报的传输契约 (端口抽象)
type Reporter interface {
	Sync(ctx context.Context, req SyncRequest) error
}

// Registry 兼容历史命名
type Registry = Reporter
