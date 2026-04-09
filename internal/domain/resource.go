package domain

import (
	"strings"

	"github.com/Duke1616/eiam/pkg/urn"
)


// Menu 菜单资源 (纯展示层元数据)
type Menu struct {
	ID             int64    `json:"id" yaml:"-"`
	ParentID       int64    `json:"parent_id" yaml:"-"`
	Name           string   `json:"name" yaml:"name"`                       // 菜单标识：对应 YAML 中的 name
	Path           string   `json:"path" yaml:"path"`                       // 路由路径：对应 YAML 中的 path
	Component      string   `json:"component" yaml:"component"`             // 前端组件：对应 JSON 中的 component
	Redirect       string   `json:"redirect" yaml:"redirect"`               // 重定向地址：对应 JSON 中的 redirect
	PermissionCode string   `json:"permission_code" yaml:"permission_code"` // 资源声明：我属于哪个逻辑权限 (URN 方案核心)
	Sort           int64    `json:"sort" yaml:"sort"`                       // 排序 (使用 Sparse Index 策略)
	Meta           MenuMeta `json:"meta" yaml:"meta"`                       // 核心 UI 控制元数据
	Ctime          int64    `json:"ctime" yaml:"-"`
	Utime          int64    `json:"utime" yaml:"-"`
	Children       []*Menu  `json:"children,omitempty" yaml:"children"` // 子菜单列表
}

func (m Menu) URN() string {
	return urn.New("iam", "menu", m.Path).String()
}

func (m Menu) GetID() int64 {
	return m.ID
}

func (m Menu) GetSortKey() int64 {
	return m.Sort
}

func (a API) URN() string {
	// 直接使用原生的 Path 模板作为唯一标识 (如 /api/:id)
	// 这在 URN 层面天然隔离了不同的路径定义，且与 Gin 的 FullPath() 完美契合
	return urn.New(a.Service, "api", strings.ToLower(a.Method)+":"+a.Path).String()
}

// MenuMeta 菜单核心 UI 控制属性
type MenuMeta struct {
	Title       string   `json:"title" yaml:"title"`               // 菜单标题
	Icon        string   `json:"icon" yaml:"icon"`                 // 图标
	IsHidden    bool     `json:"is_hidden" yaml:"is_hidden"`       // 是否隐藏
	IsAffix     bool     `json:"is_affix" yaml:"is_affix"`         // 是否固定
	IsKeepAlive bool     `json:"is_keepalive" yaml:"is_keepalive"` // 是否常驻内存
	Platforms   []string `json:"platforms" yaml:"platforms"`       // 所属平台标识
}

// API 接口资源 (纯接口层元数据)
type API struct {
	ID      int64  `json:"id"`
	Service string `json:"service"` // 所属服务标识：如 "iam", "cmdb"
	Name    string `json:"name"`    // 接口描述：如 "获取用户列表"
	Method  string `json:"method"`  // HTTP 方法：GET, POST, etc.
	Path    string `json:"path"`    // 接口路径：如 "/v1/users"
	Ctime   int64  `json:"ctime"`
	Utime   int64  `json:"utime"`
}
