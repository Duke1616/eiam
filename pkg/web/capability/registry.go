package capability

import (
	"strings"
	"sync"

	"github.com/samber/lo"
)

var (
	globalRegistriesMu sync.RWMutex
	globalRegistries   []IRegistry
	globalSortMu       sync.Mutex
	globalSort         int
)

func nextGlobalSort() int {
	globalSortMu.Lock()
	defer globalSortMu.Unlock()
	globalSort++
	return globalSort
}

// ResetGlobalRegistries 仅供单元测试重置全局状态
func ResetGlobalRegistries() {
	globalRegistriesMu.Lock()
	defer globalRegistriesMu.Unlock()
	globalRegistries = nil

	globalSortMu.Lock()
	globalSort = 0
	globalSortMu.Unlock()
}

// IRegistry 是 capability 权限注册表的统一契约
type IRegistry interface {
	PermissionProvider

	// Define 声明一个业务逻辑能力包 (推荐的纯正新设计：Define + Bind)
	Define(name, code string) *Capability

	// For 切换至指定业务领域 (自动注入 Model 的 Service, Name, Group)，用于优雅跨领域挂载能力
	For(m Model) IRegistry

	// Module 派生子模块命名空间 (彻底解决同一个 Handler 内多子业务 Code 冲突)
	Module(module string, group ...string) IRegistry

	// Sub 等同于 Module (语义别名)
	Sub(module string, group ...string) IRegistry

	// DefaultScope 设置当前注册表默认作用域
	DefaultScope(scope string) IRegistry

	// Capability 兼容历史即时声明语法
	Capability(name, code string) *Builder

	// Declare 兼容历史调用，等同于 Capability
	Declare(name, code string) *Builder

	// Attach 兼容历史语法糖：为当前接口挂靠已有能力码
	Attach(apiName, code string) *Builder

	// GetPermission 根据 code 精确检索权限元数据
	GetPermission(code string) (Permission, bool)
}

type permStore struct {
	mu   sync.RWMutex
	data map[string]*Permission
}

func newPermStore() *permStore {
	return &permStore{data: make(map[string]*Permission)}
}

type registry struct {
	service      string
	module       string
	group        string
	defaultScope string
	store        *permStore
	sort         int
}

// NewRegistry 初始化一个业务模块权限注册表
func NewRegistry(service, module, group string) IRegistry {
	r := &registry{
		service:      service,
		module:       module,
		group:        group,
		defaultScope: ScopeTenant,
		store:        newPermStore(),
	}
	registerToGlobal(r)
	return r
}

func registerToGlobal(r IRegistry) {
	globalRegistriesMu.Lock()
	defer globalRegistriesMu.Unlock()
	globalRegistries = append(globalRegistries, r)
}

func (r *registry) ProvidePermissions() []Permission {
	r.store.mu.RLock()
	defer r.store.mu.RUnlock()
	return lo.Map(lo.Values(r.store.data), func(p *Permission, _ int) Permission {
		return *p
	})
}

func (r *registry) GetPermission(code string) (Permission, bool) {
	r.store.mu.RLock()
	defer r.store.mu.RUnlock()
	p, ok := r.store.data[code]
	if !ok || p == nil {
		return Permission{}, false
	}
	return *p, true
}

func (r *registry) DefaultScope(scope string) IRegistry {
	r.defaultScope = scope
	return r
}

// Module 派生子模块命名空间（如在 codebook 下派生 "version" 或 "project"）
func (r *registry) Module(module string, group ...string) IRegistry {
	g := r.group
	if len(group) > 0 && group[0] != "" {
		g = group[0]
	}
	sub := &registry{
		service:      r.service,
		module:       module,
		group:        g,
		defaultScope: r.defaultScope,
		store:        r.store, // 共享底层存储
	}
	registerToGlobal(sub)
	return sub
}

func (r *registry) For(m Model) IRegistry {
	svc := r.service
	if m.Service != "" {
		svc = m.Service
	}
	scope := r.defaultScope
	if m.Scope != "" {
		scope = m.Scope
	}
	sub := &registry{
		service:      svc,
		module:       m.Name,
		group:        m.Group,
		defaultScope: scope,
		store:        r.store, // 共享底层存储与数据上报
	}
	registerToGlobal(sub)
	return sub
}

// Sub 派生领域内子命名空间 (自动建立 group 的树状层级递进)
func (r *registry) Sub(name string, title ...string) IRegistry {
	subModule := name
	if subModule == "" {
		subModule = r.module
	}

	groupTitle := r.group
	if len(title) > 0 && title[0] != "" {
		groupTitle = joinGroup(r.group, title[0])
	}

	sub := &registry{
		service:      r.service,
		module:       subModule,
		group:        groupTitle,
		defaultScope: r.defaultScope,
		store:        r.store,
	}
	registerToGlobal(sub)
	return sub
}

func joinGroup(parent, child string) string {
	if parent == "" {
		return child
	}
	if child == "" {
		return parent
	}
	if strings.HasPrefix(child, parent+"/") {
		return child
	}
	return parent + "/" + child
}

// Define 是核心正交入口：定义一个能力包，返回 Capability 对象供后续多路由 .Bind(...)
func (r *registry) Define(name, code string) *Capability {
	fullCode := r.normalizeCode(code)

	r.store.mu.Lock()
	existing, ok := r.store.data[fullCode]
	if !ok {
		sortVal := r.sort
		if sortVal == 0 {
			sortVal = nextGlobalSort()
			r.sort = sortVal
		}
		existing = &Permission{
			Service: r.service,
			Code:    fullCode,
			Name:    name,
			Group:   r.group,
			Scope:   r.defaultScope,
			Sort:    sortVal,
		}
		r.store.data[fullCode] = existing
	}
	r.store.mu.Unlock()

	return newCapability(r, existing)
}

func (r *registry) Capability(name, code string) *Builder {
	cap := r.Define(name, code)
	rb := cap.Route(WithName(name))
	return newBuilder(cap, rb)
}

func (r *registry) Declare(name, code string) *Builder {
	return r.Capability(name, code)
}

func (r *registry) Attach(apiName, code string) *Builder {
	fullCode := r.normalizeCode(code)

	r.store.mu.Lock()
	existing, ok := r.store.data[fullCode]
	if !ok {
		// 兜底：若此前尚未定义，自动以 apiName 初始化
		sortVal := r.sort
		if sortVal == 0 {
			sortVal = nextGlobalSort()
			r.sort = sortVal
		}
		existing = &Permission{
			Service: r.service,
			Code:    fullCode,
			Name:    apiName,
			Group:   r.group,
			Scope:   r.defaultScope,
			Sort:    sortVal,
		}
		r.store.data[fullCode] = existing
	}
	r.store.mu.Unlock()

	cap := newCapability(r, existing)
	rb := cap.Route(WithName(apiName))
	return newBuilder(cap, rb)
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
