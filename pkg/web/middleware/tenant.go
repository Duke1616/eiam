package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
)

// ActiveTenantHeaderKey 跨租户数据操作的目标租户标识 (仅限超管使用)
const ActiveTenantHeaderKey = "X-Active-Tenant-ID"

// TenancyBuilder 租户上下文中间件构建器，注入身份并设立无租户防线
type TenancyBuilder struct {
	sp     session.Provider
	logger *elog.Component
}

// NewTenancyBuilder 创建租户中间件构建器
func NewTenancyBuilder(sp session.Provider) *TenancyBuilder {
	return &TenancyBuilder{
		sp:     sp,
		logger: elog.DefaultLogger.With(elog.FieldComponentName("tenancy")),
	}
}

// Build 构建全局租户身份拦截与注入中间件
// 优先复用 Context 中的凭据，缺失时回退至本地 Session 解析
func (b *TenancyBuilder) Build() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		uid, tid := b.resolveIdentity(ctx)

		// 1. 公开未认证接口直接放行
		if uid <= 0 && tid <= 0 {
			ctx.Next()
			return
		}

		// 2. 身份已认证但未确立租户空间时的门禁拦截
		if uid > 0 && tid <= 0 {
			if !isTenantExemptPath(ctx.Request.URL.Path) {
				b.logger.Warn("已登录用户缺失有效租户空间上下文", elog.Int64("uid", uid))
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, ginx.Result{
					Code: 401002,
					Msg:  "用户未关联任何有效租户空间，请先选择或加入空间",
				})
				return
			}
		}

		// 3. 统一上下文注入 (Gin 开启 ContextWithFallback=true，Handler 可通过 ctx.Context.Value 直接读取)
		ctx.Request = ctx.Request.WithContext(ctxutil.WithUserAndTenant(ctx.Request.Context(), uid, tid))
		ctx.Next()
	}
}

// resolveIdentity 依次从 Context 和 Session 解析已认证的用户与租户信息
func (b *TenancyBuilder) resolveIdentity(ctx *gin.Context) (int64, int64) {
	uid := ctxutil.GetUserID(ctx.Request.Context()).Int64()
	tid := ctxutil.GetTenantID(ctx.Request.Context()).Int64()

	if uid == 0 && b.sp != nil {
		if sess, err := b.sp.Get(&ginx.Context{Context: ctx}); err == nil {
			uid = sess.Claims().Uid
			tid, _ = sess.Claims().Get("tenant_id").AsInt64()
		}
	}
	return uid, tid
}

// isTenantExemptPath 判断在未确立租户空间前允许放行的特权路径
func isTenantExemptPath(path string) bool {
	return strings.HasPrefix(path, "/api/tenant/switch") ||
		strings.HasPrefix(path, "/api/tenant/list/mine") ||
		path == "/api/user/logout"
}

// WithTenantOverride 路由级跨租户数据上下文覆写 (仅限系统管理员)
// 从 X-Active-Tenant-ID Header 读取目标租户，若与当前会话租户不同则覆写执行上下文
func WithTenantOverride(h gin.HandlerFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		originTid := ctxutil.GetOriginTenantID(ctx.Request.Context()).Int64()
		targetTid := ExtractTargetTid(ctx)

		// 无需覆写直接放行
		if targetTid <= 0 || targetTid == originTid {
			h(ctx)
			return
		}

		// 越权拦截：非系统管理员禁止跨租户操作
		if originTid != ctxutil.SystemTenantID {
			ctx.AbortWithStatusJSON(http.StatusForbidden, ginx.Result{
				Code: 403001,
				Msg:  "检测到跨租户越权操作，该请求已被安全拦截",
			})
			return
		}

		// 超管授权通过：覆写执行租户 tenant_id，保留身份租户 origin_tenant_id
		ctx.Request = ctx.Request.WithContext(ctxutil.WithTenantID(ctx.Request.Context(), targetTid))
		h(ctx)
	}
}

// ExtractTargetTid 从 X-Active-Tenant-ID Header 提取目标租户 ID
func ExtractTargetTid(ctx *gin.Context) int64 {
	val := ctx.GetHeader(ActiveTenantHeaderKey)
	if val == "" {
		return 0
	}
	tid, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0
	}
	return tid
}

// WTO 封装 ginx.W，自动注入 WithTenantOverride 拦截逻辑 (Without Request + Tenant Override)
func WTO(h func(*ginx.Context) (ginx.Result, error)) gin.HandlerFunc {
	return WithTenantOverride(ginx.W(h))
}

// BTO 封装 ginx.B，自动注入 WithTenantOverride 拦截逻辑 (Bind Request + Tenant Override)
func BTO[T any](h func(*ginx.Context, T) (ginx.Result, error)) gin.HandlerFunc {
	return WithTenantOverride(ginx.B(h))
}

// BSTO 封装 ginx.BS，自动注入 WithTenantOverride 拦截逻辑 (Bind + Session + Tenant Override)
func BSTO[T any](h func(*ginx.Context, T, session.Session) (ginx.Result, error)) gin.HandlerFunc {
	return WithTenantOverride(ginx.BS(h))
}
