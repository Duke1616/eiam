package ioc

import (
	"github.com/Duke1616/eiam/internal/service/resource"
	resourcehdl "github.com/Duke1616/eiam/internal/web/resource"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gotomicro/ego/server/egin"
)

// App 核心应用容器
// 统一采用能力契约（Interface）进行持有，完全剥离具体包的结构实现。
type App struct {
	// Web 容器组件
	Web *egin.Component
	// Init 资产初始化器（接口化，解耦 resource.Initializer 结构体）
	Init resource.IInitializer
	// ResourceHdl 资产同步 Web 接口
	ResourceHdl *resourcehdl.Handler
	// Providers 权限能力供应者清单
	Providers []capability.PermissionProvider
}
