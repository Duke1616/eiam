package capability

import (
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

// --- 基础模型定义 ---

const (
	ScopeSystem = "system"
	ScopeTenant = "tenant"
)

type Permission struct {
	Service string   `json:"service"`
	Code    string   `json:"code"`
	Name    string   `json:"name"`
	Group   string   `json:"group"`
	Needs   []string `json:"needs"`
	NoSync  bool     `json:"no_sync"`
	Scope   string   `json:"scope"`
}

type ResourceInfo struct {
	Name             string   `json:"name"`
	Method           string   `json:"method"`
	Path             string   `json:"path"`
	Code             string   `json:"code"`
	Needs            []string `json:"needs"`
	Group            string   `json:"group"`
	Service          string   `json:"service"`
	AllowCrossTenant bool     `json:"allow_cross_tenant"`
}

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

// --- Provider 接口定义 ---

type PermissionProvider interface {
	ProvidePermissions() []Permission
}

type MenuProvider interface {
	ProvideMenus() []Menu
}

// --- 运行时内部注册表 (并发安全优化版) ---

var (
	handlerRegistry  = make(map[uintptr]ResourceInfo)
	globalRegistries []IRegistry
)

type IRegistry interface {
	PermissionProvider
	Capability(name, code string) *Builder
	Declare(name, code string) *Builder
	DefaultScope(scope string) IRegistry

	// GetPermission 增加精确检索接口，避免全量拷贝
	GetPermission(code string) (Permission, bool)

	// 内部同步方法
	updatePermissionGroup(code string, group string)
	updatePermissionNeeds(code string, needs []string)
	updatePermissionNoSync(code string, noSync bool)
	updatePermissionScope(code string, scope string)
	updatePermissionModule(code string, module string) string
}

func NewRegistry(service, module, group string) IRegistry {
	r := &registry{
		service:      service,
		module:       module,
		group:        group,
		defaultScope: ScopeTenant,
		permissions:  make(map[string]Permission),
	}
	globalRegistries = append(globalRegistries, r)
	return r
}

type registry struct {
	mu           sync.RWMutex
	service      string
	module       string
	group        string
	defaultScope string
	permissions  map[string]Permission
}

func (r *registry) ProvidePermissions() []Permission {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return lo.Values(r.permissions)
}

func (r *registry) GetPermission(code string) (Permission, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.permissions[code]
	return p, ok
}

func (r *registry) DefaultScope(scope string) IRegistry {
	r.defaultScope = scope
	return r
}

func (r *registry) Capability(name, code string) *Builder {
	fullCode := r.normalizeCode(code)
	r.mu.Lock()
	r.permissions[fullCode] = Permission{
		Service: r.service,
		Code:    fullCode,
		Name:    name,
		Group:   r.group,
		Scope:   r.defaultScope,
	}
	r.mu.Unlock()

	return &Builder{
		registry: r,
		service:  r.service,
		name:     name,
		code:     fullCode,
	}
}

func (r *registry) Declare(name, code string) *Builder {
	return r.Capability(name, code)
}

func (r *registry) normalizeCode(code string) string {
	servicePrefix := r.service + ":"
	if strings.HasPrefix(code, servicePrefix) {
		return code
	}
	if strings.Contains(code, ":") {
		return servicePrefix + code
	}
	if r.module != "" {
		return servicePrefix + r.module + ":" + code
	}
	return servicePrefix + code
}

// 优化点：抽象通用原子更新逻辑
func (r *registry) update(code string, fn func(*Permission)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.permissions[code]; ok {
		fn(&p)
		r.permissions[code] = p
	}
}

func (r *registry) updatePermissionGroup(code string, group string) {
	r.update(code, func(p *Permission) { p.Group = group })
}

func (r *registry) updatePermissionNeeds(code string, needs []string) {
	r.update(code, func(p *Permission) { p.Needs = needs })
}

func (r *registry) updatePermissionNoSync(code string, noSync bool) {
	r.update(code, func(p *Permission) { p.NoSync = noSync })
}

func (r *registry) updatePermissionScope(code string, scope string) {
	r.update(code, func(p *Permission) { p.Scope = scope })
}

func (r *registry) updatePermissionModule(code string, module string) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.permissions[code]
	if !ok {
		return code
	}

	delete(r.permissions, code)
	// 优化点：健壮的模块替换逻辑，支持多级编码
	parts := strings.Split(code, ":")
	var newActionPart string
	if len(parts) >= 3 {
		// 之前是 service:module:action... 格式，保留从第三部分开始的所有内容
		newActionPart = strings.Join(parts[2:], ":")
	} else {
		newActionPart = lo.LastOr(parts, "")
	}

	p.Code = fmt.Sprintf("%s:%s:%s", r.service, module, newActionPart)
	p.Service = r.service
	r.permissions[p.Code] = p
	return p.Code
}

// --- Builder 链式装饰器 ---

type Builder struct {
	registry         IRegistry
	service          string
	name             string
	code             string
	allowCrossTenant bool
}

func (b *Builder) Group(group string) *Builder {
	if b.registry != nil {
		b.registry.updatePermissionGroup(b.code, group)
	}
	return b
}

func (b *Builder) Needs(codes ...string) *Builder {
	if b.registry != nil {
		b.registry.updatePermissionNeeds(b.code, codes)
	}
	return b
}

func (b *Builder) NoSync() *Builder {
	if b.registry != nil {
		b.registry.updatePermissionNoSync(b.code, true)
	}
	return b
}

func (b *Builder) Scope(scope string) *Builder {
	if b.registry != nil {
		b.registry.updatePermissionScope(b.code, scope)
	}
	return b
}

func (b *Builder) Module(module string) *Builder {
	if b.registry != nil {
		b.code = b.registry.updatePermissionModule(b.code, module)
	}
	return b
}

func (b *Builder) AllowCrossTenant() *Builder {
	b.allowCrossTenant = true
	return b
}

func (b *Builder) Handle(h gin.HandlerFunc) gin.HandlerFunc {
	ptr := reflect.ValueOf(h).Pointer()
	if b.registry != nil {
		if p, ok := b.registry.GetPermission(b.code); ok {
			handlerRegistry[ptr] = ResourceInfo{
				Service:          b.service,
				Name:             b.name,
				Code:             b.code,
				Needs:            p.Needs,
				Group:            p.Group,
				AllowCrossTenant: b.allowCrossTenant,
			}
		}
	}
	return h
}

// GetResourceInfo 运行时检索 (供中间件使用)
func GetResourceInfo(ptr uintptr) (ResourceInfo, bool) {
	info, ok := handlerRegistry[ptr]
	return info, ok
}

// --- Collector 资产收集器 ---

type Collector struct {
	providers     []PermissionProvider
	menuProviders []MenuProvider
	engine        *gin.Engine
	service       string // 显式 Service 覆写 (通常从 Permission/ResourceInfo 自动推导)
}

func NewCollector() *Collector {
	return &Collector{}
}

type SyncOption func(*Collector)

func WithPermissions(p ...PermissionProvider) SyncOption {
	return func(c *Collector) { c.providers = append(c.providers, p...) }
}
func WithMenus(m ...MenuProvider) SyncOption {
	return func(c *Collector) { c.menuProviders = append(c.menuProviders, m...) }
}
func WithRouter(engine *gin.Engine) SyncOption {
	return func(c *Collector) { c.engine = engine }
}
func WithService(name string) SyncOption {
	return func(c *Collector) { c.service = name }
}

func (c *Collector) Collect(opts ...SyncOption) SyncRequest {
	for _, opt := range opts {
		opt(c)
	}

	req := SyncRequest{
		Permissions: c.collectPermissions(),
		APIs:        c.collectAPIs(),
		Menus:       c.collectMenus(),
	}

	// Service 推导：优先显式覆写 → Permission → ResourceInfo
	if c.service != "" {
		req.Service = c.service
	} else if len(req.Permissions) > 0 {
		req.Service = req.Permissions[0].Service
	} else if len(req.APIs) > 0 {
		req.Service = req.APIs[0].Service
	}

	return req
}

func (c *Collector) collectPermissions() []Permission {
	providerPerms := lo.FlatMap(c.providers, func(p PermissionProvider, _ int) []Permission {
		return p.ProvidePermissions()
	})
	globalPerms := lo.FlatMap(globalRegistries, func(r IRegistry, _ int) []Permission {
		return r.ProvidePermissions()
	})

	uniquePermsMap := lo.Associate(lo.Concat(globalPerms, providerPerms), func(p Permission) (string, Permission) {
		return p.Code, p
	})

	return lo.Filter(lo.Values(uniquePermsMap), func(p Permission, _ int) bool {
		return !p.NoSync
	})
}

func (c *Collector) collectAPIs() []ResourceInfo {
	if c.engine == nil {
		return nil
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
	return apis
}

func (c *Collector) collectMenus() []Menu {
	return lo.FlatMap(c.menuProviders, func(p MenuProvider, _ int) []Menu {
		return p.ProvideMenus()
	})
}
