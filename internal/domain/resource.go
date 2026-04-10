package domain

import (
	"strings"

	"github.com/Duke1616/eiam/pkg/urn"
	"github.com/Duke1616/eiam/pkg/utils"
)

// MenuTree 定义菜单树类型，代表具有层级嵌套关系的菜单集合
type MenuTree []*Menu

// MenuList 定义扁平菜单列表类型，代表打平后用于物理存储或传输的切片
type MenuList []Menu

// Flatten 将层级结构的菜单树打平为扁平切片，并自动修正 ParentName 拓扑
func (t MenuTree) Flatten() MenuList {
	var res MenuList
	utils.WalkHierarchical[*Menu](t, func(m *Menu) []*Menu {
		return m.Children
	}, func(m *Menu, parent *Menu) {
		if parent != nil {
			m.ParentName = parent.Name
		} else {
			m.ParentName = ""
		}
		res = append(res, *m)
	})
	return res
}

// ToTree 将扁平列表转换为层级树结构，并按 Sort 字段排序
func (l MenuList) ToTree() MenuTree {
	nodeMap := make(map[int64]*Menu)
	for i := range l {
		menu := l[i]
		menu.Children = make([]*Menu, 0)
		nodeMap[menu.ID] = &menu
	}

	var roots MenuTree
	for _, m := range nodeMap {
		if m.ParentID == 0 {
			roots = append(roots, m)
		} else {
			if parent, exists := nodeMap[m.ParentID]; exists {
				parent.Children = append(parent.Children, m)
			}
		}
	}

	// 递归逻辑已扁平化为 Map 遍历，只需对各层级执行排序
	for _, m := range nodeMap {
		if len(m.Children) > 1 {
			utils.SortBySortKey(m.Children)
		}
	}
	utils.SortBySortKey(roots)

	return roots
}

// Menu 菜单资源 (纯展示层元数据)
type Menu struct {
	ID             int64    `json:"id" yaml:"-"`
	ParentID       int64    `json:"parent_id" yaml:"-"`
	ParentName     string   `json:"parent_name" yaml:"-"` // 父级名称缓存，用于拓扑解析
	Name           string   `json:"name" yaml:"name"`     // 菜单标识
	Path           string   `json:"path" yaml:"path"`     // 路由路径
	Component      string   `json:"component" yaml:"component"`             // 前端组件
	Redirect       string   `json:"redirect" yaml:"redirect"`               // 重定向地址
	PermissionCode string   `json:"permission_code" yaml:"permission_code"` // 资源声明
	Sort           int64    `json:"sort" yaml:"sort"`                       // 排序
	Meta           MenuMeta `json:"meta" yaml:"meta"`                       // UI 控制元数据
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
	return urn.New(a.Service, "api", strings.ToLower(a.Method)+":"+a.Path).String()
}

// MenuMeta 菜单核心 UI 控制属性
type MenuMeta struct {
	Title       string   `json:"title" yaml:"title"`
	Icon        string   `json:"icon" yaml:"icon"`
	IsHidden    bool     `json:"is_hidden" yaml:"is_hidden"`
	IsAffix     bool     `json:"is_affix" yaml:"is_affix"`
	IsKeepAlive bool     `json:"is_keepalive" yaml:"is_keepalive"`
	Platforms   []string `json:"platforms" yaml:"platforms"`
}

// API 接口资源
type API struct {
	ID      int64  `json:"id"`
	Service string `json:"service"`
	Name    string `json:"name"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Ctime   int64  `json:"ctime"`
	Utime   int64  `json:"utime"`
}
