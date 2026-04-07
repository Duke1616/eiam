package ioc

import (
	"github.com/Duke1616/eiam/internal/web/permission"
	"github.com/Duke1616/eiam/internal/web/role"
	"github.com/Duke1616/eiam/pkg/web/capability"
)

// InitProviders 将核心领域 Handler 聚合为 SDK 暴露的 PermissionProvider 接口。
func InitProviders(capabilityHdl *permission.Handler, roleHdl *role.Handler) []capability.PermissionProvider {
	return []capability.PermissionProvider{
		capabilityHdl,
		roleHdl,
	}
}
