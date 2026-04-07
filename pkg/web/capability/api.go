package capability

import (
	"reflect"

	"github.com/gin-gonic/gin"
)

// Permission 权限项定义 (逻辑能力包)
type Permission struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Group string `json:"group"`
}

// PermissionProvider 定义了逻辑权限能力项的供应接口
type PermissionProvider interface {
	ProvidePermissions() []Permission
}

// ResourceInfo 存储 API 资产在 SDK 内部发现的元数据
type ResourceInfo struct {
	Name    string `json:"name"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Codes   []string `json:"codes"`
	Service string `json:"service"`
}

var (
	// handlerRegistry 运行时内存注册表
	handlerRegistry = make(map[uintptr]ResourceInfo)
)

// Capability 声明 API 的元数据。
func Capability(name string, codes ...string) func(gin.HandlerFunc) gin.HandlerFunc {
	return func(h gin.HandlerFunc) gin.HandlerFunc {
		ptr := reflect.ValueOf(h).Pointer()
		handlerRegistry[ptr] = ResourceInfo{
			Name:  name,
			Codes: codes,
		}
		return h
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
