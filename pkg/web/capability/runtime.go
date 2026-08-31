package capability

import (
	"sync"
)

// IRuntimeRegistry 定义运行时 Handler 路由与元数据的映射契约
type IRuntimeRegistry interface {
	// Register 将路由 Handler 函数指针与其物理资源元数据绑定
	Register(ptr uintptr, info ResourceInfo)
	// Get 根据 Handler 函数指针检索其物理资源元数据
	Get(ptr uintptr) (ResourceInfo, bool)
	// Reset 重置注册表状态 (通常用于单测或动态重载)
	Reset()
}

type runtimeRegistry struct {
	mu   sync.RWMutex
	data map[uintptr]ResourceInfo
}

// NewRuntimeRegistry 构造一个新的运行时注册表实例
func NewRuntimeRegistry() IRuntimeRegistry {
	return &runtimeRegistry{
		data: make(map[uintptr]ResourceInfo),
	}
}

func (r *runtimeRegistry) Register(ptr uintptr, info ResourceInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[ptr] = info
}

func (r *runtimeRegistry) Get(ptr uintptr) (ResourceInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	info, ok := r.data[ptr]
	return info, ok
}

func (r *runtimeRegistry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data = make(map[uintptr]ResourceInfo)
}

// --- 全局默认单例与门面函数 (保证向后完全兼容) ---

var (
	defaultRuntimeMu sync.RWMutex
	defaultRuntime   = NewRuntimeRegistry()
)

// DefaultRuntime 获取全局默认运行时注册表
func DefaultRuntime() IRuntimeRegistry {
	defaultRuntimeMu.RLock()
	defer defaultRuntimeMu.RUnlock()
	return defaultRuntime
}

// SetDefaultRuntime 允许测试或定制扩展时覆写全局运行时注册表
func SetDefaultRuntime(r IRuntimeRegistry) {
	defaultRuntimeMu.Lock()
	defer defaultRuntimeMu.Unlock()
	defaultRuntime = r
}

// GetResourceInfo 运行时检索 (供 Gin 中间件鉴权时快速反查元数据)
func GetResourceInfo(ptr uintptr) (ResourceInfo, bool) {
	return DefaultRuntime().Get(ptr)
}

// ResetRuntimeRegistry 重置全局运行时状态 (供单元测试隔离使用)
func ResetRuntimeRegistry() {
	DefaultRuntime().Reset()
}
