package middleware

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CorsBuilder 运用建造者模式 (Builder Pattern) 动态装配 CORS 中间件，彻底解耦业务特定 Header
type CorsBuilder struct {
	allowOrigins  []string
	allowMethods  []string
	allowHeaders  []string
	exposeHeaders []string
	maxAge        time.Duration
}

// NewCorsBuilder 初始化跨域建造者，注入符合云原生标准的默认值
func NewCorsBuilder() *CorsBuilder {
	return &CorsBuilder{
		allowOrigins:  []string{"*"},
		allowMethods:  []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		allowHeaders:  []string{ActiveTenantHeaderKey, "Content-Type", "Authorization"},
		exposeHeaders: []string{"X-Access-Token", "X-Token-Carrier"},
		maxAge:        12 * time.Hour,
	}
}

// AllowOrigins 覆盖配置允许的源 (如配置具体域名以支持 AllowCredentials)
func (b *CorsBuilder) AllowOrigins(origins ...string) *CorsBuilder {
	b.allowOrigins = origins
	return b
}

// AddOrigins 向已有允许的源列表中追加新源
func (b *CorsBuilder) AddOrigins(origins ...string) *CorsBuilder {
	b.allowOrigins = append(b.allowOrigins, origins...)
	return b
}

// AllowMethods 覆盖配置允许的 HTTP 方法
func (b *CorsBuilder) AllowMethods(methods ...string) *CorsBuilder {
	b.allowMethods = methods
	return b
}

// AddMethods 向已有允许的 HTTP 方法列表中追加新方法
func (b *CorsBuilder) AddMethods(methods ...string) *CorsBuilder {
	b.allowMethods = append(b.allowMethods, methods...)
	return b
}

// AllowHeaders 链式动态注入允许的自定义请求头
func (b *CorsBuilder) AllowHeaders(headers ...string) *CorsBuilder {
	b.allowHeaders = append(b.allowHeaders, headers...)
	return b
}

// ExposeHeaders 链式动态注入暴露给前端的自定义响应头
func (b *CorsBuilder) ExposeHeaders(headers ...string) *CorsBuilder {
	b.exposeHeaders = append(b.exposeHeaders, headers...)
	return b
}

// MaxAge 设置跨域预检请求缓存时间
func (b *CorsBuilder) MaxAge(duration time.Duration) *CorsBuilder {
	b.maxAge = duration
	return b
}

// Build 最终构建出符合 Gin 规范的 HandlerFunc
func (b *CorsBuilder) Build() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowOrigins:     b.allowOrigins,
		AllowMethods:     b.allowMethods,
		AllowHeaders:     b.allowHeaders,
		ExposeHeaders:    b.exposeHeaders,
		AllowCredentials: true,
		MaxAge:           b.maxAge,
	})
}
