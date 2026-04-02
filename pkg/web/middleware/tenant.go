package middleware

import (
	"strconv"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

// ExtractTenantID 租户上下文解析中间件
func ExtractTenantID(sp session.Provider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 根据示例修正：gctx.Context 的 Context 字段应传入 *gin.Context
		sess, err := sp.Get(&gctx.Context{Context: ctx})
		if err != nil {
			// 未登录或公开路由，直接跳过
			ctx.Next()
			return
		}

		// 从 Session 中提取写入的租户 ID
		// NOTE: 假设通过存储为 string 的方式
		tidVal := sess.Get(ctx.Request.Context(), "tenant_id")
		tidStr, err := tidVal.String()
		if err == nil && tidStr != "" {
			tid, _ := strconv.ParseInt(tidStr, 10, 64)
			
			// 注入到标准 Go Context 中，以备后续 Service/DAO 提取
			newCtx := ctxutil.WithTenantID(ctx.Request.Context(), tid)
			newCtx = ctxutil.WithUserID(newCtx, sess.Claims().Uid)
			
			ctx.Request = ctx.Request.WithContext(newCtx)
		}

		ctx.Next()
	}
}
