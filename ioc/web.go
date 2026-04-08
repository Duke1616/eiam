package ioc

import (
	"net"
	"time"

	"github.com/Duke1616/eiam/internal/pkg/middleware"
	"github.com/Duke1616/eiam/internal/service/permission"
	permissionhdl "github.com/Duke1616/eiam/internal/web/permission"
	"github.com/Duke1616/eiam/internal/web/policy"
	resourcehdl "github.com/Duke1616/eiam/internal/web/resource"
	"github.com/Duke1616/eiam/internal/web/role"
	"github.com/Duke1616/eiam/internal/web/tenant"
	"github.com/Duke1616/eiam/internal/web/user"
	pkgmiddleware "github.com/Duke1616/eiam/pkg/web/middleware"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/econf"
	"github.com/gotomicro/ego/core/elog"
	"github.com/gotomicro/ego/server/egin"
)

func InitGinWebServer(sp session.Provider, listener net.Listener, mdls []gin.HandlerFunc,
	userHdl *user.Handler, policyHdl *policy.Handler,
	tenantHdl *tenant.Handler, permissionHdl *permissionhdl.Handler,
	roleHdl *role.Handler, resourceHdl *resourcehdl.Handler,
	permSvc permission.IPermissionService) *egin.Component {
	session.SetDefaultProvider(sp)

	server := egin.Load("server.egin").Build(egin.WithListener(listener))
	server.Use(mdls...)

	// 1. 注册公开路由 (无鉴权)
	userHdl.PublicRoutes(server.Engine)
	policyHdl.PublicRoutes(server.Engine)
	tenantHdl.PublicRoutes(server.Engine)
	resourceHdl.PublicRoutes(server.Engine)

	// 2. 登录层：验证是否登录
	server.Use(session.CheckLoginMiddleware())

	// 3. 基础权限层：仅需登录即可访问的私有接口 (如获取菜单)
	permissionHdl.PrivateRoutes(server.Engine)

	// 4. API 业务鉴权层：基于 RBAC/OPA 的细粒度权限校验
	server.Use(middleware.CheckPermission(permSvc))

	// 5. 注册业务私有路由 (必须通过 OPA 判定)
	userHdl.PrivateRoutes(server.Engine)
	policyHdl.PrivateRoutes(server.Engine)
	tenantHdl.PrivateRoutes(server.Engine)
	roleHdl.PrivateRoutes(server.Engine)
	resourceHdl.PrivateRoutes(server.Engine)

	return server
}

func InitGinMiddlewares(sp session.Provider) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		corsHdl(),
		accessLogger(),
		pkgmiddleware.ExtractTenantID(sp),
	}
}

func corsHdl() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		ExposeHeaders:    []string{"x-jwt-token", "x-refresh-token"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})
}

// accessLogger 自定义 access 日志中间件
func accessLogger() gin.HandlerFunc {
	// 关闭默认的日志输出
	econf.Set("server.egin.enableAccessInterceptor", false)

	// ego DefaultLogger 针对框架内部做了 caller skip 校准，直接 from 用户代码调用需减一层
	logger := elog.DefaultLogger.With(elog.FieldComponentName("access")).WithCallerSkip(-1)
	return func(ctx *gin.Context) {
		beg := time.Now()
		ctx.Next()
		cost := time.Since(beg)

		fields := []elog.Field{
			elog.FieldMethod(ctx.Request.Method + "." + ctx.FullPath()),
			elog.FieldAddr(ctx.Request.URL.RequestURI()),
			elog.FieldCost(cost),
			elog.FieldCode(int32(ctx.Writer.Status())),
		}

		logger.Info("access", fields...)
	}
}
