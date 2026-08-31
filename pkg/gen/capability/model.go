package capability

import (
	"fmt"
	"slices"
	"strings"
)

// Scope 作用域类型
type Scope string

const (
	ScopeTenant Scope = "tenant"
	ScopeSystem Scope = "system"
)

// Chinese 返回作用域的优雅中文展示名称
func (s Scope) Chinese() string {
	switch s {
	case ScopeSystem:
		return "系统级"
	case ScopeTenant:
		return "租户级"
	default:
		return string(s)
	}
}

// Action 原子级受控权限定义
type Action struct {
	Service      string   // 所属服务，如 "iam"
	Module       string   // 所属业务领域模块，如 "user"
	SubModule    string   // 衍生子模块，如 "ldap"
	OriginModule string   // 声明所在的宿主模块，如 "policy" (用于检测跨域)
	Action       string   // 原始动作码，如 "edit"
	Code         string   // 规范化完整权限码，如 "iam:user:edit"
	Name         string   // 权限操作展示名称，如 "修改用户"
	Needs        []string // 声明的前置依赖权限码列表
	NoSync       bool     // 是否标记为静默接口 (不上报权限中心，前端不暴露分配)
	Scope        Scope    // 作用域 (tenant / system)
	File         string   // 声明所在的物理源文件
	Line         int      // 源码所在行号
}

// TagChinese 返回用于 Go 契约结构体注释的优雅中文标签，如 "租户级 · 跨域: policy · 静默"
func (a *Action) TagChinese() string {
	parts := []string{a.Scope.Chinese()}

	if a.SubModule != "" {
		parts = append(parts, "子级")
	} else if a.OriginModule != "" && a.OriginModule != a.Module {
		parts = append(parts, fmt.Sprintf("跨域: %s", a.OriginModule))
	}

	if a.NoSync {
		parts = append(parts, "静默")
	}

	return strings.Join(parts, " · ")
}

// KindChinese 返回权限在 Markdown 文档中的分类描述
func (a *Action) KindChinese() string {
	if a.SubModule != "" {
		return fmt.Sprintf("子级 (%s)", a.SubModule)
	}
	if a.OriginModule != "" && a.OriginModule != a.Module {
		return fmt.Sprintf("跨域 (%s)", a.OriginModule)
	}
	return "本级"
}

// SyncStatusChinese 返回权限同步至 IAM 权限树的状态描述
func (a *Action) SyncStatusChinese() string {
	if a.NoSync {
		return "静默 (不暴露)"
	}
	return "正常"
}

// FullCode 计算规范化完整权限码
func (a *Action) FullCode() string {
	if strings.Contains(a.Action, ":") {
		return a.Action
	}
	if a.SubModule != "" {
		return fmt.Sprintf("%s:%s.%s:%s", a.Service, a.Module, a.SubModule, a.Action)
	}
	return fmt.Sprintf("%s:%s:%s", a.Service, a.Module, a.Action)
}

// PropertyName 生成在 Go 结构体或 TS 中的大驼峰属性标识符
func (a *Action) PropertyName() string {
	raw := a.Action
	if a.SubModule != "" {
		raw = a.SubModule + "_" + a.Action
	}
	return ToPascalCase(raw)
}

// Module 业务领域模块定义
type Module struct {
	Service      string
	Name         string
	Title        string
	DefaultScope Scope
	File         string
	Actions      []*Action
}

// ID 返回模块唯一标识符，如 "iam:user"
func (m *Module) ID() string {
	return fmt.Sprintf("%s:%s", m.Service, m.Name)
}

// ModelVarName 生成在 pkg/contract/model 包中导出的常量名，如 "User", "Role"
func (m *Module) ModelVarName() string {
	return ToPascalCase(m.Name)
}

// StructName 生成 Go 强类型契约结构体的导出标识符
func (m *Module) StructName() string {
	return ToPascalCase(m.Name)
}

// SortedActions 返回按 PropertyName 字典序排列的权限切片 (确保输出确定性)
func (m *Module) SortedActions() []*Action {
	res := make([]*Action, len(m.Actions))
	copy(res, m.Actions)
	slices.SortFunc(res, func(a, b *Action) int {
		return strings.Compare(a.PropertyName(), b.PropertyName())
	})
	return res
}

// Graph 全局聚合后的权限拓扑图
type Graph struct {
	CapabilityPkg string             // 从源码 import 中提取的 SDK 路径 (如 "github.com/Duke1616/eiam/pkg/web/capability")
	ProjectName   string             // 当前工程名称 (如 "EIAM", "ETASK")
	Modules       map[string]*Module // ID -> Module
	Actions       map[string]*Action // Code -> Action
}

// DocTitle 返回大盘文档的自适应标题
func (g *Graph) DocTitle() string {
	if g.ProjectName != "" {
		return fmt.Sprintf("%s 全局权限大盘与元数据字典", g.ProjectName)
	}
	return "全局权限大盘与元数据字典"
}

// NewGraph 初始化空拓扑图
func NewGraph() *Graph {
	return &Graph{
		Modules: make(map[string]*Module),
		Actions: make(map[string]*Action),
	}
}

// AddAction 将权限点注册至图中 (相同 Code 自动去重并合并 Needs)
func (g *Graph) AddAction(act *Action) {
	act.Code = act.FullCode()
	modID := fmt.Sprintf("%s:%s", act.Service, act.Module)

	mod, ok := g.Modules[modID]
	if !ok {
		mod = &Module{
			Service: act.Service,
			Name:    act.Module,
			File:    act.File,
		}
		g.Modules[modID] = mod
	}

	if existing, exists := g.Actions[act.Code]; exists {
		for _, need := range act.Needs {
			if !slices.Contains(existing.Needs, need) {
				existing.Needs = append(existing.Needs, need)
			}
		}
		return
	}

	mod.Actions = append(mod.Actions, act)
	g.Actions[act.Code] = act
}

// SortedModules 返回按模块 StructName 字典序排列的模块列表
func (g *Graph) SortedModules() []*Module {
	res := make([]*Module, 0, len(g.Modules))
	for _, m := range g.Modules {
		res = append(res, m)
	}
	slices.SortFunc(res, func(a, b *Module) int {
		return strings.Compare(a.StructName(), b.StructName())
	})
	return res
}

// Issue 诊断发现的健康异常项
type Issue struct {
	Severity   string // ERROR / WARN
	File       string
	Line       int
	ActionCode string
	Message    string
	Suggestion string
}
