package capability

import (
	"reflect"

	"github.com/gin-gonic/gin"
)

// Permission 权限项定义 (逻辑权限项)
type Permission struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Group string `json:"group"`
}

// PermissionProvider 定义了逻辑权限能力项的供应接口
type PermissionProvider interface {
	ProvidePermissions() []Permission
}

// ResourceInfo 存储 API 资产在 SDK 内部发现的元数据
type ResourceInfo struct {
	Name         string   `json:"name"`
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	Code         string   `json:"code"`         // 主绑定权限码 (Primary)
	Dependencies []string `json:"dependencies"` // 关联依赖权限码 (Dependencies)
	Group        string   `json:"group"`
	Service      string   `json:"service"`
}

var (
	// handlerRegistry 运行时内存注册表
	handlerRegistry = make(map[uintptr]ResourceInfo)
)

// Builder 辅助构建 API 能力声明
type Builder struct {
	registry     IRegistry
	name         string
	code         string
	group        string
	dependencies []string
}

// Group 设置权限所属分组
func (b *Builder) Group(group string) *Builder {
	b.group = group
	if b.registry != nil {
		b.registry.updatePermissionGroup(b.code, group)
	}
	return b
}

// Dependency 声明依赖的其他权限码（仅作为依赖，不参与本 API 的主权限绑定）
func (b *Builder) Dependency(codes ...string) *Builder {
	b.dependencies = append(b.dependencies, codes...)
	return b
}

// Handle 将能力声明应用到指定的 Gin Handler 上
func (b *Builder) Handle(h gin.HandlerFunc) gin.HandlerFunc {
	ptr := reflect.ValueOf(h).Pointer()
	handlerRegistry[ptr] = ResourceInfo{
		Name:         b.name,
		Code:         b.code,
		Dependencies: b.dependencies,
		Group:        b.group,
	}
	return h
}

// IRegistry 权限注册中心接口
type IRegistry interface {
	PermissionProvider
	// Capability 在注册中心声明一个与 API 绑定的能力
	Capability(name, code string) *Builder
	// Declare 仅在注册中心声明一个逻辑权限（如菜单权限），不直接绑定到 API
	Declare(name, code string) *Builder
	// updatePermissionGroup 内部方法：用于在链式调用中同步更新权限分组
	updatePermissionGroup(code string, group string)
}

// registry 权限注册中心默认实现
type registry struct {
	defaultGroup string
	permissions  map[string]Permission
}

// NewRegistry 创建一个新的权限注册中心实例
func NewRegistry(group string) IRegistry {
	return &registry{
		defaultGroup: group,
		permissions:  make(map[string]Permission),
	}
}

func (r *registry) Capability(name, code string) *Builder {
	r.permissions[code] = Permission{
		Code:  code,
		Name:  name,
		Group: r.defaultGroup,
	}
	return &Builder{
		registry: r,
		name:     name,
		code:     code,
		group:    r.defaultGroup,
	}
}

func (r *registry) Declare(name, code string) *Builder {
	return r.Capability(name, code)
}

func (r *registry) updatePermissionGroup(code string, group string) {
	if p, ok := r.permissions[code]; ok {
		p.Group = group
		r.permissions[code] = p
	}
}

func (r *registry) ProvidePermissions() []Permission {
	perms := make([]Permission, 0, len(r.permissions))
	for _, p := range r.permissions {
		perms = append(perms, p)
	}
	return perms
}

// Capability 声明 API 的元数据入口 (全局独立模式)
func Capability(name string, code string) *Builder {
	return &Builder{
		name: name,
		code: code,
	}
}

// Collector 资源收集器
type Collector struct {
	providers []PermissionProvider
	engine    *gin.Engine
}

func NewCollector(engine *gin.Engine) *Collector {
	return &Collector{
		engine: engine,
	}
}

func (c *Collector) RegisterProviders(p ...PermissionProvider) *Collector {
	c.providers = append(c.providers, p...)
	return c
}

// Collect 执行全量资产收集
// 优化了 API 扫描逻辑，通过卫语句避免深层嵌套，并预分配切片容量提升性能
func (c *Collector) Collect() ([]Permission, []ResourceInfo) {
	// 1. 收集逻辑权限
	var perms []Permission
	for _, p := range c.providers {
		perms = append(perms, p.ProvidePermissions()...)
	}

	// 2. 收集物理 API 资产
	if c.engine == nil {
		return perms, nil
	}

	routes := c.engine.Routes()
	apis := make([]ResourceInfo, 0, len(routes))
	for _, route := range routes {
		ptr := reflect.ValueOf(route.HandlerFunc).Pointer()
		info, ok := handlerRegistry[ptr]
		if !ok {
			continue
		}

		info.Method = route.Method
		info.Path = route.Path
		apis = append(apis, info)
	}

	return perms, apis
}
