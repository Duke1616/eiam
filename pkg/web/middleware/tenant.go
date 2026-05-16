package middleware

import (
	"net/http"
	"strconv"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
)

// TenancyBuilder 租户中间件构建器，封装 session.Provider 和 logger
// IOC 层通过 NewTenancyBuilder(sp).Build() 注册全局中间件
//
// 用法:
//
//	builder := middleware.NewTenancyBuilder(sp)
//	server.Use(builder.Build())
//	// 路由级: WithTenantOverride / WithTenantSwitch 无需 builder，直接使用包级函数
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

// Build 构建全局租户身份注入中间件 (InjectIdentity)
// 在登录校验之后、业务路由之前执行，是身份上下文的基础设施
func (b *TenancyBuilder) Build() gin.HandlerFunc {
	if b.sp == nil {
		b.sp = session.DefaultProvider()
	}

	return func(ctx *gin.Context) {
		gCtx := &ginx.Context{Context: ctx}
		sess, err := b.sp.Get(gCtx)
		if err != nil {
			gCtx.AbortWithStatus(http.StatusForbidden)
			b.logger.Debug("用户未登录", elog.FieldErr(err))
			return
		}

		claims := sess.Claims()
		currentTid, _ := claims.Get("tenant_id").AsInt64()

		// 注入 context.WithValue (仅单通道)
		// Gin Engine 已开启 ContextWithFallback=true，handler 通过 ctx.Context.Value() 可直接读取
		//
		// 语义区分：
		//   tenant_id        = 执行租户 (操作谁的数据 → GORM 数据隔离)
		//   origin_tenant_id = 身份租户 (你是谁 → 鉴权校验)
		// 注入时两者相同；后续 WithTenantOverride 只覆写 tenant_id，origin_tenant_id 保留会话真实身份
		newCtx := ctxutil.WithUserID(ctx.Request.Context(), claims.Uid)
		newCtx = ctxutil.WithTenantID(newCtx, currentTid)
		newCtx = ctxutil.WithOriginTenantID(newCtx, currentTid)
		ctx.Request = ctx.Request.WithContext(newCtx)

		ctx.Next()
	}
}

// WithTenantOverride 路由级跨租户上下文覆写 (仅限系统管理员)
//
// 从 X-Tenant-ID Header 读取目标租户，若与当前会话租户不同则覆写上下文
// 仅系统管理员 (tenant_id=1) 允许跨租户操作，普通用户将被安全拦截
//
// 适用场景：超管在系统空间下管理其他租户的数据 (如查租户成员、管理角色等)
// 替代原全局 GuardCrossTenant 对非白名单路由的拦截逻辑
//
// 用法:
//
//	g.POST("/members", WithTenantOverride(
//	    h.Capability("查看租户成员", "view_members").
//	        Scope(capability.ScopeTenant).
//	        Handle(ginx.B[ListMembersReq](h.ListMembers)),
//	))
func WithTenantOverride(h gin.HandlerFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 鉴权看身份租户 (你是谁)，不是执行租户 (操作谁的数据)
		originTid := ctxutil.GetOriginTenantID(ctx.Request.Context()).Int64()
		targetTid := extractTargetTid(ctx)

		if targetTid == 0 || targetTid == originTid {
			h(ctx)
			return
		}

		// 安全校验：只有系统级管理员允许跨租户操作
		if originTid != ctxutil.SystemTenantID {
			ctx.AbortWithStatusJSON(http.StatusForbidden, ginx.Result{
				Code: 403001,
				Msg:  "检测到跨租户越权操作，该请求已被安全拦截",
			})
			return
		}

		// 授权通过（超管）：仅覆写执行租户 (tenant_id)
		// origin_tenant_id 保留会话真实身份 (1=系统租户)，鉴权时仍可识别超管身份
		newCtx := ctxutil.WithTenantID(ctx.Request.Context(), targetTid)
		ctx.Request = ctx.Request.WithContext(newCtx)

		h(ctx)
	}
}

// WithTenantSwitch 路由级租户切换 (无需系统管理员权限)
//
// 从 X-Tenant-ID Header 读取目标租户，若与当前会话租户不同则覆写上下文
// 不做超管校验，handler 层负责校验用户是否属于目标租户 (如 CheckUserTenantAccess)
//
// 适用场景：租户切换路由，普通用户也需要切换自己的租户空间
// 替代原全局 GuardCrossTenant 对 AllowCrossTenant 白名单路由的放行逻辑
//
// 用法:
//
//	g.POST("/switch", WithTenantSwitch(
//	    h.Capability("切换租户", "switch").
//	        AllowCrossTenant().
//	        Handle(ginx.W(h.SwitchTenant)),
//	))
func WithTenantSwitch(h gin.HandlerFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 用身份租户判断是否需要覆写 (与执行租户初始值相同)
		originTid := ctxutil.GetOriginTenantID(ctx.Request.Context()).Int64()
		targetTid := extractTargetTid(ctx)

		if targetTid == 0 || targetTid == originTid {
			h(ctx)
			return
		}

		// 覆写执行租户 (tenant_id)，origin_tenant_id 保留会话真实身份
		// handler 层负责校验用户是否属于目标租户 (如 CheckUserTenantAccess)
		newCtx := ctxutil.WithTenantID(ctx.Request.Context(), targetTid)
		ctx.Request = ctx.Request.WithContext(newCtx)

		h(ctx)
	}
}

// extractTargetTid 从请求中提取目标租户 ID
// 仅从 X-Tenant-ID Header 读取
func extractTargetTid(ctx *gin.Context) int64 {
	val := ctx.GetHeader("X-Tenant-ID")

	if val == "" {
		return 0
	}
	tid, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0
	}
	return tid
}
