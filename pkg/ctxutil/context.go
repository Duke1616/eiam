package ctxutil

import (
	"context"
	"strconv"
)

// 定义核心 Context Key 常量
const (
	// TenantIDKey 当前操作的目标租户 ID (数据平面)
	TenantIDKey = "tenant_id"

	// OriginTenantIDKey 用户的原始身份租户 ID (身份平面)
	OriginTenantIDKey = "origin_tenant_id"

	// UserIDKey 当前登录用户的唯一标识 ID
	UserIDKey = "user_id"

	// UsernameKey 当前登录用户的账号名
	UsernameKey = "username"

	// SystemTenantID 系统根租户 ID (母体租户)
	SystemTenantID int64 = 1

	// SystemTenantIDStr 字符串格式，用于 Casbin 域等场景
	SystemTenantIDStr = "1"

	// ClientIPKey 客户端访问 IP 地址
	ClientIPKey = "client_ip"

	// UserAgentKey 客户端浏览器 UserAgent
	UserAgentKey = "user_agent"
)

// ContextID 对 int64 的包装，提供便捷的转换方法
type ContextID int64

func (id ContextID) String() string {
	return strconv.FormatInt(int64(id), 10)
}

func (id ContextID) Int64() int64 {
	return int64(id)
}

// Get [通用泛型提取]
func Get[T any](ctx context.Context, key string) T {
	if ctx == nil {
		var zero T
		return zero
	}
	val := ctx.Value(key)
	if res, ok := val.(T); ok {
		return res
	}
	var zero T
	return zero
}

// With [通用泛型注入]
func With[T any](ctx context.Context, key string, val T) context.Context {
	return context.WithValue(ctx, key, val)
}

// GetTenantID 快捷获取租户 ID
func GetTenantID(ctx context.Context) ContextID {
	return ContextID(Get[int64](ctx, TenantIDKey))
}

// GetUserID 快捷获取用户 ID
func GetUserID(ctx context.Context) ContextID {
	return ContextID(Get[int64](ctx, UserIDKey))
}

// GetOriginTenantID 快捷获取原始身份租户 ID (家谱)
func GetOriginTenantID(ctx context.Context) ContextID {
	return ContextID(Get[int64](ctx, OriginTenantIDKey))
}

// GetUsername 快捷获取登录用户名
func GetUsername(ctx context.Context) string {
	return Get[string](ctx, UsernameKey)
}

// WithTenantID 注入租户 ID
func WithTenantID(ctx context.Context, tid int64) context.Context {
	return With(ctx, TenantIDKey, tid)
}

// WithUserID 注入用户 ID
func WithUserID(ctx context.Context, uid int64) context.Context {
	return With(ctx, UserIDKey, uid)
}

// WithOriginTenantID 注入原始身份租户 ID
func WithOriginTenantID(ctx context.Context, tid int64) context.Context {
	return With(ctx, OriginTenantIDKey, tid)
}

// WithUserAndTenant 一次性注入用户 ID 与租户上下文 (涵盖执行租户与原始身份租户)
func WithUserAndTenant(ctx context.Context, uid, tid int64) context.Context {
	return WithOriginTenantID(WithTenantID(WithUserID(ctx, uid), tid), tid)
}

// WithUserInfo 一次性注入完整登录用户信息 (ID、租户ID与用户名)
func WithUserInfo(ctx context.Context, uid, tid int64, username string) context.Context {
	return With(WithUserAndTenant(ctx, uid, tid), UsernameKey, username)
}

type privateOnlyKey struct{}

// WithPrivateOnly 标记该 Context 下的查询仅返回私有资产，忽略共享资源
func WithPrivateOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, privateOnlyKey{}, true)
}

// IsPrivateOnly 检查是否处于“仅限私有资产”模式
func IsPrivateOnly(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	val, _ := ctx.Value(privateOnlyKey{}).(bool)
	return val
}

// GetClientIP 快捷获取请求端 IP 地址
func GetClientIP(ctx context.Context) string {
	return Get[string](ctx, ClientIPKey)
}

// GetUserAgent 快捷获取请求端浏览器 UserAgent
func GetUserAgent(ctx context.Context) string {
	return Get[string](ctx, UserAgentKey)
}

// WithClientInfo 快捷注入请求端网络与环境特征 (用于审计日志与安全风控)
func WithClientInfo(ctx context.Context, ip, userAgent string) context.Context {
	return With(With(ctx, ClientIPKey, ip), UserAgentKey, userAgent)
}

