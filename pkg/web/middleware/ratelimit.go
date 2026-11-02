package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/middlewares/ratelimit"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"github.com/redis/go-redis/v9"
)

// Config 限流中间件配置定义 (映射配置文件中的 web.ratelimit 节点)
type Config struct {
	Enabled     bool `mapstructure:"enabled"`
	DefaultRate int  `mapstructure:"default_rate"`
}

// IRateLimiter 通用分布式限流器标准接口
type IRateLimiter interface {
	// Limit 通用 IP 维度限流 (适用于常规公开接口)
	Limit(rate int, interval time.Duration) gin.HandlerFunc

	// LimitAuth 敏感认证防爆破限流 (基于 IP + Path，默认 1 分钟 default_rate 次，支持显式传参覆盖)
	LimitAuth(rates ...int) gin.HandlerFunc

	// LimitWith 自定义维度生成 Key 的限流中间件
	LimitWith(rate int, interval time.Duration, keyGen func(*gin.Context) string) gin.HandlerFunc
}

// rateLimiter 分布式滑动窗口限流器实现
type rateLimiter struct {
	cmd         redis.Cmdable
	defaultRate int
	logger      *elog.Component
}

// NewRateLimiter 创建限流器实例 (面向接口编程，支持依赖注入与外部项目独立复用)
func NewRateLimiter(cmd redis.Cmdable, cfg Config) IRateLimiter {
	rate := cfg.DefaultRate
	if rate <= 0 {
		rate = 10
	}

	return &rateLimiter{
		cmd:         cmd,
		defaultRate: rate,
		logger:      elog.DefaultLogger.With(elog.FieldComponentName("ratelimit")),
	}
}

// Limit 通用 IP 维度限流 (单 IP 在 interval 窗口内最多允许 rate 次请求)
func (r *rateLimiter) Limit(rate int, interval time.Duration) gin.HandlerFunc {
	return r.LimitWith(rate, interval, func(ctx *gin.Context) string {
		return fmt.Sprintf("eiam:ratelimit:ip:%s", ctx.ClientIP())
	})
}

// LimitAuth 敏感认证防爆破限流 (IP + Path 绑定防撞库，未传参时自动继承 default_rate，默认窗口为 1 分钟)
func (r *rateLimiter) LimitAuth(rates ...int) gin.HandlerFunc {
	rate := r.defaultRate
	if len(rates) > 0 && rates[0] > 0 {
		rate = rates[0]
	}

	return r.LimitWith(rate, time.Minute, func(ctx *gin.Context) string {
		return fmt.Sprintf("eiam:ratelimit:auth:%s:%s", ctx.ClientIP(), ctx.Request.URL.Path)
	})
}

// LimitWith 自定义维度生成 Key 的限流中间件
func (r *rateLimiter) LimitWith(rate int, interval time.Duration, keyGen func(*gin.Context) string) gin.HandlerFunc {
	if r.cmd == nil {
		return func(c *gin.Context) { c.Next() }
	}

	limiter := ratelimit.NewRedisSlidingWindowLimiter(r.cmd, interval, rate)

	return func(ctx *gin.Context) {
		key := keyGen(ctx)
		limited, err := limiter.Limit(ctx.Request.Context(), key)
		if err != nil {
			// Fail-Open 高可用降级：Redis 偶发抖动或超时直接放行并告警，避免认证服务雪崩
			r.logger.Warn("限流组件 Redis 执行异常", elog.FieldErr(err), elog.String("key", key))
			ctx.Next()
			return
		}

		if limited {
			r.logger.Warn("请求触发频控限流策略已被拦截",
				elog.String("client_ip", ctx.ClientIP()),
				elog.String("path", ctx.Request.URL.Path),
				elog.String("key", key),
			)
			ctx.AbortWithStatusJSON(http.StatusTooManyRequests, ginx.Result{
				Code: 429001,
				Msg:  "请求过于频繁，请稍后重试",
			})
			return
		}

		ctx.Next()
	}
}

// =========================================================================
// 包级便捷门面 (Global Facade) —— 供 Handler 子路由组无侵入直调
// =========================================================================

var defaultLimiter IRateLimiter = &noopLimiter{}

// InitDefaultRateLimiter 初始化全局限流器 (在 ioc 启动时挂载)
func InitDefaultRateLimiter(cmd redis.Cmdable, cfg Config) IRateLimiter {
	if !cfg.Enabled || cmd == nil {
		defaultLimiter = &noopLimiter{}
		return defaultLimiter
	}
	defaultLimiter = NewRateLimiter(cmd, cfg)
	return defaultLimiter
}

// SetDefaultRateLimiterForTest 仅供单元测试注入 Mock 限流器
func SetDefaultRateLimiterForTest(l IRateLimiter) {
	defaultLimiter = l
}

// LimitAuth 全局开箱即用的敏感认证防爆破中间件 (默认 1 分钟 default_rate 次，支持显式传参覆盖)
func LimitAuth(rates ...int) gin.HandlerFunc {
	return defaultLimiter.LimitAuth(rates...)
}

// Limit 全局开箱即用的通用 IP 频控中间件
func Limit(rate int, interval time.Duration) gin.HandlerFunc {
	return defaultLimiter.Limit(rate, interval)
}

// LimitWith 全局开箱即用的自定义维度限流中间件
func LimitWith(rate int, interval time.Duration, keyGen func(*gin.Context) string) gin.HandlerFunc {
	return defaultLimiter.LimitWith(rate, interval, keyGen)
}

// noopLimiter 空实现：配置未启用或测试无 Redis 依赖时安全直通
type noopLimiter struct{}

func (n *noopLimiter) Limit(int, time.Duration) gin.HandlerFunc                     { return func(c *gin.Context) { c.Next() } }
func (n *noopLimiter) LimitAuth(...int) gin.HandlerFunc                             { return func(c *gin.Context) { c.Next() } }
func (n *noopLimiter) LimitWith(int, time.Duration, func(*gin.Context) string) gin.HandlerFunc { return func(c *gin.Context) { c.Next() } }
