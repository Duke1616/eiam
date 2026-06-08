package ioc

import (
	"net"

	"github.com/Duke1616/eiam/internal/pkg/middleware"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/web/discovery"
	idhdl "github.com/Duke1616/eiam/internal/web/identity_source"
	invitationhdl "github.com/Duke1616/eiam/internal/web/invitation"
	permissionhdl "github.com/Duke1616/eiam/internal/web/permission"
	"github.com/Duke1616/eiam/internal/web/policy"
	rolehdl "github.com/Duke1616/eiam/internal/web/role"
	tenanthdl "github.com/Duke1616/eiam/internal/web/tenant"
	"github.com/Duke1616/eiam/internal/web/user"
	"github.com/Duke1616/eiam/internal/web/department"
	"github.com/Duke1616/eiam/internal/web/group"
	pkgmiddleware "github.com/Duke1616/eiam/pkg/web/middleware"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/server/egin"
)

func InitGinWebServer(sp session.Provider, listener net.Listener, mdls []gin.HandlerFunc,
	userHdl *user.Handler, policyHdl *policy.Handler,
	tenantHdl *tenanthdl.Handler, permissionHdl *permissionhdl.Handler,
	roleHdl *rolehdl.Handler,
	deptHdl *department.Handler, groupHdl *group.Handler,
	identitySourceHdl *idhdl.Handler, invitationHdl *invitationhdl.Handler,
	discoveryHdl *discovery.Handler, tenancyBuilder *pkgmiddleware.TenancyBuilder,
	permSvc permission.IPermissionService) *egin.Component {
	session.SetDefaultProvider(sp)

	server := egin.Load("server.egin").Build(egin.WithListener(listener))
	// 开启 ContextWithFallback：使 ctx.Context.Value() 自动 fallback 到 ctx.Request.Context().Value()
	// 这样 ctxutil.GetTenantID(ctx.Context) 无需 ctx.Set 双通道注入即可正确读取
	server.Engine.ContextWithFallback = true
	server.Use(mdls...)

	// 1. 注册公开路由 (无鉴权)
	userHdl.PublicRoutes(server.Engine)
	policyHdl.PublicRoutes(server.Engine)
	tenantHdl.PublicRoutes(server.Engine)
	permissionHdl.PublicRoutes(server.Engine)
	identitySourceHdl.PublicRoutes(server.Engine)
	invitationHdl.PublicRoutes(server.Engine)
	discoveryHdl.PublicRoutes(server.Engine)

	// 2. 登录层：验证是否登录
	server.Use(session.CheckLoginMiddleware())
	// 2.1 租户身份构建
	server.Use(tenancyBuilder.Build())

	// 3. 基础权限层：仅需登录即可访问的私有接口 (如获取菜单)
	permissionHdl.IdentityRoutes(server.Engine)
	userHdl.IdentityRoutes(server.Engine)
	tenantHdl.IdentityRoutes(server.Engine)
	invitationHdl.IdentityRoutes(server.Engine)

	// 4. API 业务鉴权层：基于 RBAC/OPA 的细粒度权限校验
	server.Use(middleware.CheckPermission(permSvc))

	// 5. 注册业务私有路由 (必须通过 OPA 判定)
	userHdl.PrivateRoutes(server.Engine)
	policyHdl.PrivateRoutes(server.Engine)
	tenantHdl.PrivateRoutes(server.Engine)
	roleHdl.PrivateRoutes(server.Engine)
	deptHdl.PrivateRoutes(server.Engine)
	groupHdl.PrivateRoutes(server.Engine)
	permissionHdl.PrivateRoutes(server.Engine)
	identitySourceHdl.PrivateRoutes(server.Engine)
	invitationHdl.PrivateRoutes(server.Engine)

	return server
}

func InitGinMiddlewares() []gin.HandlerFunc {
	return []gin.HandlerFunc{
		pkgmiddleware.NewCorsBuilder().Build(),
		pkgmiddleware.AccessLogger(),
	}
}
