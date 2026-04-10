package middleware

import (
	"strconv"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

// BuildContext 租户与用户信息上下文解析注入中间件
func BuildContext(sp session.Provider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 容错处理：不因 Session 脏数据（如 Malformed Token）阻塞流程
		sess, err := sp.Get(&gctx.Context{Context: ctx})
		if err != nil {
			// 直接跳过，让后续业务逻辑或认证中间件决定是否拦截
			ctx.Next()
			return
		}

		// 提取租户 ID
		tid, _ := strconv.ParseInt(sess.Claims().Data["tenant_id"], 10, 64)
		uid := sess.Claims().Uid

		// 1. 注入 Gin 上下文 (Web层使用)
		ctx.Set("uid", uid)
		ctx.Set("tenant_id", tid)

		// 2. 注入标准 Context (确保下游 Service/DAO 可见)
		newCtx := ctxutil.WithUserID(ctx.Request.Context(), uid)
		newCtx = ctxutil.WithTenantID(newCtx, tid)
		ctx.Request = ctx.Request.WithContext(newCtx)

		ctx.Next()
	}
}
