package capability

import (
	"strings"

	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/gin-gonic/gin"
)

// Builder 兼容历史链式语法的构建器
// 底层直接基于工整的 Capability 与 RouteBinding 驱动，零破坏兼容所有老代码
type Builder struct {
	cap *Capability
	rb  *RouteBinding
}

func newBuilder(cap *Capability, rb *RouteBinding) *Builder {
	return &Builder{
		cap: cap,
		rb:  rb,
	}
}

func (b *Builder) Group(group string) *Builder {
	b.cap.Group(group)
	return b
}

func (b *Builder) Needs(codes ...string) *Builder {
	b.cap.Needs(codes...)
	return b
}

func (b *Builder) NoSync() *Builder {
	b.cap.NoSync()
	return b
}

func (b *Builder) Scope(scope string) *Builder {
	b.cap.Scope(scope)
	return b
}

func (b *Builder) AllowCrossTenant() *Builder {
	b.rb.AllowCrossTenant()
	return b
}

func (b *Builder) AccessScope(profile pbac.FilterProfile, presets ...pbac.AccessScopePreset) *Builder {
	b.cap.AccessScope(profile, presets...)
	b.rb.filterProfile = profile
	return b
}

// Module 动态修改当前能力的模块命名空间 (兼容老代码中的后置 .Module() 调用)
func (b *Builder) Module(module string) *Builder {
	if b.cap == nil || module == "" {
		return b
	}

	parts := strings.SplitN(b.cap.perm.Code, ":", 3)
	var action string
	switch len(parts) {
	case 3:
		action = parts[2]
	case 2:
		action = parts[1]
	default:
		return b
	}

	oldCode := b.cap.perm.Code
	newCode := b.cap.perm.Service + ":" + module + ":" + action

	b.cap.reg.store.mu.Lock()
	delete(b.cap.reg.store.data, oldCode)
	b.cap.perm.Code = newCode
	b.cap.reg.store.data[newCode] = b.cap.perm
	b.cap.reg.store.mu.Unlock()

	return b
}

// Handle 装饰 Gin Handler，完成物理接口与权限元数据的最终绑定
func (b *Builder) Handle(h gin.HandlerFunc) gin.HandlerFunc {
	return b.rb.Handle(h)
}
