package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/econf"
	"github.com/gotomicro/ego/core/elog"
)

// AccessLogger 自定义 access 访问日志中间件，提供符合 ego 框架规范的调用链路追踪
func AccessLogger() gin.HandlerFunc {
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
