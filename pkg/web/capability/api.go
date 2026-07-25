package capability

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

// --- 基础模型定义 ---

const (
	ScopeSystem = "system"
	ScopeTenant = "tenant"
)

type Permission struct {
	Service            string                   `json:"service"`
	Code               string                   `json:"code"`
	Name               string                   `json:"name"`
	Group              string                   `json:"group"`
	Needs              []string                 `json:"needs"`
	NoSync             bool                     `json:"no_sync"`
	Scope              string                   `json:"scope"`
	Sort               int                      `json:"sort"`
	AccessScopePresets []pbac.AccessScopePreset `json:"access_scope_presets,omitempty"`
}

type ResourceInfo struct {
	Name             string             `json:"name"`
	Method           string             `json:"method"`
	Path             string             `json:"path"`
	Code             string             `json:"code"`
	Needs            []string           `json:"needs"`
	Group            string             `json:"group"`
	Service          string             `json:"service"`
	AllowCrossTenant bool               `json:"allow_cross_tenant"`
	FilterProfile    pbac.FilterProfile `json:"filter_profile,omitempty"`
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
	handlerRegistryMu sync.RWMutex
	handlerRegistry   = make(map[uintptr]ResourceInfo)
	globalRegistries  []IRegistry
)

// IRegistry 是 capability 注册表的公共接口，供 Handler 嵌入使用。
type IRegistry interface {
	PermissionProvider
	Capability(name, code string) *Builder
	Declare(name, code string) *Builder
	DefaultScope(scope string) IRegistry

	// GetPermission 根据 code 精确检索权限元数据，避免全量拷贝
	GetPermission(code string) (Permission, bool)
}

// internalRegistry 是 registry 内部接口，仅供 Builder 链式调用回调使用。
type internalRegistry interface {
	IRegistry
	updatePermissionGroup(code string, group string)
	updatePermissionNeeds(code string, needs []string)
	updatePermissionNoSync(code string, noSync bool)
	updatePermissionScope(code string, scope string)
	updatePermissionModule(code string, module string) string
	updatePermissionAccessScopePresets(code string, presets []pbac.AccessScopePreset)
}

var (
	globalSortMu sync.Mutex
	globalSort   int
)

func nextGlobalSort() int {
	globalSortMu.Lock()
	defer globalSortMu.Unlock()
	globalSort++
	return globalSort
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
	sort         int
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

	if r.sort == 0 {
		r.sort = nextGlobalSort()
	}

	r.permissions[fullCode] = Permission{
		Service: r.service,
		Code:    fullCode,
		Name:    name,
		Group:   r.group,
		Scope:   r.defaultScope,
		Sort:    r.sort,
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

func (r *registry) updatePermissionAccessScopePresets(code string, presets []pbac.AccessScopePreset) {
	r.update(code, func(p *Permission) { p.AccessScopePresets = presets })
}

func (r *registry) updatePermissionModule(code string, module string) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.permissions[code]
	if !ok {
		return code
	}

	// code 格式: service[:oldModule]:action...
	// 用 SplitN 最多分 3 段，保留 service 和 action，替换 module
	parts := strings.SplitN(code, ":", 3)
	var action string
	switch len(parts) {
	case 3:
		action = parts[2]
	case 2:
		action = parts[1]
	default:
		return code
	}

	newCode := fmt.Sprintf("%s:%s:%s", r.service, module, action)
	delete(r.permissions, code)
	p.Code = newCode
	p.Service = r.service
	r.permissions[newCode] = p
	return newCode
}

// --- Builder 链式装饰器 ---

type Builder struct {
	registry         internalRegistry
	service          string
	name             string
	code             string
	allowCrossTenant bool
	filterProfile    pbac.FilterProfile
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

// AccessScope 声明当前 API 消费 AccessScope 时使用的固定编译 profile，
// presets 是由业务服务提供给策略编辑器的可选模板，不影响运行时鉴权语义。
func (b *Builder) AccessScope(profile pbac.FilterProfile, presets ...pbac.AccessScopePreset) *Builder {
	if strings.TrimSpace(string(profile)) == "" {
		panic("capability filter profile must not be empty")
	}
	seen := make(map[string]struct{}, len(presets))
	for i := range presets {
		preset := &presets[i]
		preset.Code = strings.TrimSpace(preset.Code)
		preset.Name = strings.TrimSpace(preset.Name)
		if preset.Code == "" || preset.Name == "" || preset.Expression == nil {
			panic("capability AccessScope preset requires code, name and expression")
		}
		if _, ok := seen[preset.Code]; ok {
			panic("duplicate capability AccessScope preset: " + preset.Code)
		}
		seen[preset.Code] = struct{}{}
		if err := pbac.ValidateAccessScope(preset.Expression); err != nil {
			panic("invalid capability AccessScope preset " + preset.Code + ": " + err.Error())
		}
	}
	b.filterProfile = profile
	if b.registry != nil {
		b.registry.updatePermissionAccessScopePresets(b.code, slices.Clone(presets))
	}
	return b
}

func (b *Builder) Handle(h gin.HandlerFunc) gin.HandlerFunc {
	ptr := reflect.ValueOf(h).Pointer()
	if b.registry != nil {
		if p, ok := b.registry.GetPermission(b.code); ok {
			handlerRegistryMu.Lock()
			handlerRegistry[ptr] = ResourceInfo{
				Service:          b.service,
				Name:             b.name,
				Code:             b.code,
				Needs:            p.Needs,
				Group:            p.Group,
				AllowCrossTenant: b.allowCrossTenant,
				FilterProfile:    b.filterProfile,
			}
			handlerRegistryMu.Unlock()
		}
	}
	return h
}

// GetResourceInfo 运行时检索 (供中间件使用)
func GetResourceInfo(ptr uintptr) (ResourceInfo, bool) {
	handlerRegistryMu.RLock()
	defer handlerRegistryMu.RUnlock()
	info, ok := handlerRegistry[ptr]
	return info, ok
}

// --- Collector 资产收集器 ---

type Collector struct {
	providers     []PermissionProvider
	menuProviders []MenuProvider
	engine        *gin.Engine
	service       string // 显式 Service 覆写 (通常从 Permission/ResourceInfo 自动推导)
	source        string
	apiPathPrefix string
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
func WithSource(source string) SyncOption {
	return func(c *Collector) { c.source = strings.TrimSpace(source) }
}
func WithAPIPathPrefix(prefix string) SyncOption {
	return func(c *Collector) { c.apiPathPrefix = normalizePathPrefix(prefix) }
}

func (c *Collector) Collect(opts ...SyncOption) SyncRequest {
	for _, opt := range opts {
		opt(c)
	}

	req := SyncRequest{
		Source:      c.source,
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
	seen := make(map[string]struct{})
	var perms []Permission

	// 1. 收集显式提供的权限
	for _, provider := range c.providers {
		for _, p := range provider.ProvidePermissions() {
			if !p.NoSync {
				if _, ok := seen[p.Code]; !ok {
					seen[p.Code] = struct{}{}
					perms = append(perms, p)
				}
			}
		}
	}

	// 2. 收集全局注册表中的权限（显式提供者优先，后续覆盖）
	for _, reg := range globalRegistries {
		for _, p := range reg.ProvidePermissions() {
			if !p.NoSync {
				if _, ok := seen[p.Code]; !ok {
					seen[p.Code] = struct{}{}
					perms = append(perms, p)
				}
			}
		}
	}

	// 3. 对收集到的所有权限点进行物理注册时序（Sort）的升序排序
	slices.SortFunc(perms, func(a, b Permission) int {
		return a.Sort - b.Sort
	})

	return perms
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
		info.Path = applyPathPrefix(c.apiPathPrefix, route.Path)
		apis = append(apis, info)
	}
	return apis
}

func (c *Collector) collectMenus() []Menu {
	return lo.FlatMap(c.menuProviders, func(p MenuProvider, _ int) []Menu {
		return p.ProvideMenus()
	})
}

func normalizePathPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return ""
	}
	return "/" + strings.Trim(prefix, "/")
}

func applyPathPrefix(prefix string, routePath string) string {
	routePath = strings.TrimSpace(routePath)
	if routePath == "" {
		routePath = "/"
	}
	if !strings.HasPrefix(routePath, "/") {
		routePath = "/" + routePath
	}
	if prefix == "" {
		return routePath
	}
	if routePath == "/" {
		return prefix
	}
	return prefix + routePath
}
