//go:build wireinject

package ioc

import (
	"github.com/Duke1616/eiam/internal/service/discovery"
	"github.com/google/wire"
)

// InitApp 统一编排并装配完整企业级 EIAM 应用服务实例
func InitApp() (*App, error) {
	wire.Build(
		BaseSet,
		UserSet,
		TenantSet,
		RoleSet,
		PermissionSet,
		DepartmentSet,
		GroupSet,
		InvitationSet,
		ResourceSet,
		AuditSet,
		WebSet,
		GrpcSet,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}

// InitTokenService 为 CLI Token 生成命令提供专用的轻量级依赖注入树 (Wire 原生自动编排，仅需 DB 依赖)
func InitTokenService() (discovery.ITokenService, error) {
	wire.Build(
		InitDBWithoutMigrate,
		TokenCliSet,
	)
	return nil, nil
}



