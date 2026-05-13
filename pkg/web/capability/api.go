package capability

import (
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
)

// Permission 权限项定义 (逻辑权限项)
const (
	ScopeSystem = "system" // 仅系统租户 (TID=1) 可见/可用
	ScopeTenant = "tenant" // 所有租户可见/可用 (默认)
)

type Permission struct {
	Service string   `json:"service"`
	Code    string   `json:"code"`
	Name    string   `json:"name"`
	Group   string   `json:"group"`
	Needs   []string `json:"needs"`
	NoSync  bool     `json:"no_sync"` // 标识该权限项是否不进行数据库同步
	Scope   string   `json:"scope"`   // 权限作用域
}

// PermissionProvider 定义了逻辑权限能力项的供应接口
type PermissionProvider interface {
	ProvidePermissions() []Permission
}

// ResourceInfo 存储 API 资产在 SDK 内部发现的元数据
type ResourceInfo struct {
	Name             string   `json:"name"`
	Method           string   `json:"method"`
	Path             string   `json:"path"`
	Code             string   `json:"code"`  // 主绑定权限码 (Primary)
	Needs            []string `json:"needs"` // 关联依赖权限码 (Needs)
	Group            string   `json:"group"`
	Service          string   `json:"service"`
	AllowCrossTenant bool     `json:"allow_cross_tenant"` // 标识该资源是否允许跨租户操作 (针对超管穿透)
}

var (
	// handlerRegistry 运行时内存注册表
	handlerRegistry = make(map[uintptr]ResourceInfo)

	// globalRegistries 自动发现：记录所有已实例化的注册中心
	globalRegistries []IRegistry
)

// GetResourceInfo 根据 Handler 指针获取关联的资源元数据
func GetResourceInfo(ptr uintptr) (ResourceInfo, bool) {
	info, ok := handlerRegistry[ptr]
	return info, ok
}

// Builder 辅助构建 API 能力声明
type Builder struct {
	registry         IRegistry
	service          string
	name             string
	code             string
	group            string
	needs            []string
	allowCrossTenant bool
	noSync           bool
	scope            string
	module           string
}

// Group 设置权限所属分组
func (b *Builder) Group(group string) *Builder {
	b.group = group
	if b.registry != nil {
		b.registry.updatePermissionGroup(b.code, group)
	}
	return b
}

// Needs 声明依赖的其他权限码（仅作为依赖，不参与本 API 的主权限绑定）
func (b *Builder) Needs(codes ...string) *Builder {
	b.needs = append(b.needs, codes...)
	if b.registry != nil {
		b.registry.updatePermissionNeeds(b.code, b.needs)
	}
	return b
}

// AllowCrossTenant 声明该 API 允许跨租户操作 (通常针对穿透逻辑)
func (b *Builder) AllowCrossTenant() *Builder {
	b.allowCrossTenant = true
	return b
}

// NoSync 声明该能力项不需要同步到数据库
func (b *Builder) NoSync() *Builder {
	b.noSync = true
	if b.registry != nil {
		b.registry.updatePermissionNoSync(b.code, true)
	}
	return b
}

// Scope 设置权限作用域
func (b *Builder) Scope(scope string) *Builder {
	b.scope = scope
	if b.registry != nil {
		b.registry.updatePermissionScope(b.code, scope)
	}
	return b
}

// Module 覆盖权限所属模块 (用于跨模块能力映射)
func (b *Builder) Module(module string) *Builder {
	b.module = module
	if b.registry != nil {
		b.code = b.registry.updatePermissionModule(b.code, module)
	}
	return b
}

// Handle 将能力声明应用到指定的 Gin Handler 上
func (b *Builder) Handle(h gin.HandlerFunc) gin.HandlerFunc {
	ptr := reflect.ValueOf(h).Pointer()
	handlerRegistry[ptr] = ResourceInfo{
		Service:          b.service,
		Name:             b.name,
		Code:             b.code,
		Needs:            b.needs,
		Group:            b.group,
		AllowCrossTenant: b.allowCrossTenant,
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
	// DefaultScope 设置注册中心默认权限作用域
	DefaultScope(scope string) IRegistry
	// updatePermissionGroup 内部方法：用于在链式调用中同步更新权限分组
	updatePermissionGroup(code string, group string)
	// updatePermissionNeeds 内部方法：用于在链式调用中同步更新权限依赖
	updatePermissionNeeds(code string, needs []string)
	// updatePermissionNoSync 内部方法：用于在链式调用中同步更新同步标志
	updatePermissionNoSync(code string, noSync bool)
	// updatePermissionScope 内部方法：用于在链式调用中同步更新作用域
	updatePermissionScope(code string, scope string)
	// updatePermissionModule 内部方法：用于在链式调用中同步更新所属模块
	updatePermissionModule(code string, module string) string
}

// registry 权限注册中心默认实现
type registry struct {
	service      string
	module       string
	group        string
	defaultScope string
	permissions  map[string]Permission
}

// NewRegistry 创建一个新的权限注册中心实例
func NewRegistry(service, module, group string) IRegistry {
	r := &registry{
		service:      service,
		module:       module,
		group:        group,
		defaultScope: ScopeTenant,
		permissions:  make(map[string]Permission),
	}

	// 自动注册到全局列表，实现零配置自动发现
	globalRegistries = append(globalRegistries, r)
	return r
}

func (r *registry) DefaultScope(scope string) IRegistry {
	r.defaultScope = scope
	return r
}

func (r *registry) Capability(name, code string) *Builder {
	fullCode := r.normalizeCode(code)
	r.permissions[fullCode] = Permission{
		Service: r.service,
		Code:    fullCode,
		Name:    name,
		Group:   r.group,
		Scope:   r.defaultScope,
	}
	return &Builder{
		registry: r,
		service:  r.service,
		name:     name,
		code:     fullCode,
		group:    r.group,
		scope:    r.defaultScope,
	}
}

func (r *registry) Declare(name, code string) *Builder {
	return r.Capability(name, code)
}

func (r *registry) normalizeCode(code string) string {
	// 场景 1：已经是完整路径 (eiam:iam:user:add) 或已包含服务 (iam:user:add)
	// 判断标准：以 service: 开头
	servicePrefix := r.service + ":"
	if len(code) >= len(servicePrefix) && code[:len(servicePrefix)] == servicePrefix {
		return code
	}

	// 场景 2：包含模块但缺少服务 (user:add)
	// 判断标准：包含 ":"
	hasDelimiter := false
	for i := 0; i < len(code); i++ {
		if code[i] == ':' {
			hasDelimiter = true
			break
		}
	}
	if hasDelimiter {
		return servicePrefix + code
	}

	// 场景 3：极致精简方案 (add -> iam:role:add)
	// 判断标准：仅有动作
	if r.module != "" {
		return servicePrefix + r.module + ":" + code
	}

	return servicePrefix + code
}

func (r *registry) updatePermissionGroup(code string, group string) {
	if p, ok := r.permissions[code]; ok {
		p.Group = group
		r.permissions[code] = p
	}
}
func (r *registry) updatePermissionNeeds(code string, needs []string) {
	if p, ok := r.permissions[code]; ok {
		p.Needs = needs
		r.permissions[code] = p
	}
}

func (r *registry) updatePermissionNoSync(code string, noSync bool) {
	if p, ok := r.permissions[code]; ok {
		p.NoSync = noSync
		r.permissions[code] = p
	}
}

func (r *registry) updatePermissionScope(code string, scope string) {
	if p, ok := r.permissions[code]; ok {
		p.Scope = scope
		r.permissions[code] = p
	}
}

func (r *registry) updatePermissionModule(code string, module string) string {
	if p, ok := r.permissions[code]; ok {
		// 重新生成完整的 Code
		oldCode := p.Code
		delete(r.permissions, oldCode)

		p.Code = r.service + ":" + module + ":" + strings.Split(oldCode, ":")[len(strings.Split(oldCode, ":"))-1]
		r.permissions[p.Code] = p
		return p.Code
	}
	return code
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
	// 1. 收集逻辑权限 (支持显式 Provider + 全局自动发现)
	var perms []Permission
	uniquePerms := make(map[string]Permission)

	// 处理显式注册的 Provider (高优先级)
	for _, p := range c.providers {
		for _, perm := range p.ProvidePermissions() {
			uniquePerms[perm.Code] = perm
		}
	}

	// 处理自动发现的注册中心 (补全漏注的情况)
	for _, r := range globalRegistries {
		for _, perm := range r.ProvidePermissions() {
			if _, ok := uniquePerms[perm.Code]; !ok {
				uniquePerms[perm.Code] = perm
			}
		}
	}

	for _, p := range uniquePerms {
		perms = append(perms, p)
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
