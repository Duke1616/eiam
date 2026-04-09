package middleware

import (
	"net/http"
	"reflect"

	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

// CheckPermission 内部鉴权中间件
// 用于 EIAM 自身服务的 API 权限校验
func CheckPermission(svc permission.IPermissionService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 1. 获取登录态
		sess, err := session.Get(&gctx.Context{Context: ctx})
		if err != nil || sess == nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		uid := sess.Claims().Uid

		// 2. 识别当前请求对应的逻辑元数据
		// 通过 Gin 的 HandlerFunc 指针反查在路由注册时通过 h.Capability 注入的信息
		ptr := reflect.ValueOf(ctx.Handler()).Pointer()
		info, ok := capability.GetResourceInfo(ptr)
		if !ok {
			// 未通过 h.Capability 注册的私有路由，默认视为“仅需登录”即可访问 (如 /menus)
			// 如果需要更严格的权限控制，可以在此处改为 Abort
			ctx.Next()
			return
		}

		// 3. 调用权限服务执行判定
		// 执行逻辑：物理资产发现 -> 逻辑权限匹配 -> OPA 策略演算
		ok, err = svc.CheckAPI(ctx.Request.Context(), uid, info.Service, ctx.Request.Method, ctx.FullPath())
		if err != nil {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if !ok {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}

		ctx.Next()
	}
}
