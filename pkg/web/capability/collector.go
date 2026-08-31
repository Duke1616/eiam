package capability

import (
	"reflect"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

// Collector 资产扫描器
type Collector struct {
	providers     []PermissionProvider
	menuProviders []MenuProvider
	engine        *gin.Engine
	service       string
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

// Collect 扫描并汇聚所有权限、API 与菜单元数据
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
	globalRegistriesMu.RLock()
	regs := slices.Clone(globalRegistries)
	globalRegistriesMu.RUnlock()

	// 统一汇聚所有显式与全局 Provider
	providers := make([]PermissionProvider, 0, len(c.providers)+len(regs))
	providers = append(providers, c.providers...)
	for _, reg := range regs {
		providers = append(providers, reg)
	}

	// 提取全部权限 -> 过滤 NoSync -> 按 Code 唯一去重
	allPerms := lo.FlatMap(providers, func(p PermissionProvider, _ int) []Permission {
		return p.ProvidePermissions()
	})

	validPerms := lo.Filter(allPerms, func(p Permission, _ int) bool {
		return !p.NoSync
	})

	perms := lo.UniqBy(validPerms, func(p Permission) string {
		return p.Code
	})

	// 按注册权重 Sort 升序排序
	slices.SortFunc(perms, func(a, b Permission) int {
		return a.Sort - b.Sort
	})

	return perms
}

func (c *Collector) collectAPIs() []ResourceInfo {
	if c.engine == nil {
		return nil
	}

	runtime := DefaultRuntime()

	// 过滤并映射已注册 Capability 的路由端点
	return lo.FilterMap(c.engine.Routes(), func(route gin.RouteInfo, _ int) (ResourceInfo, bool) {
		ptr := reflect.ValueOf(route.HandlerFunc).Pointer()
		info, ok := runtime.Get(ptr)
		if !ok {
			return ResourceInfo{}, false
		}
		info.Method = route.Method
		info.Path = applyPathPrefix(c.apiPathPrefix, route.Path)
		return info, true
	})
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
