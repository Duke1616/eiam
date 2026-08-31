package ctxutil

import (
	"context"
	"strconv"
)

// 定义常用的 Key 常量
const (
	// TenantIDKey 当前操作的目标租户 ID (数据平面)
	// 在常规请求中，它等于用户所属租户；在超管穿透 (Roaming) 场景下，它指向被操作的目标租户，用于数据库隔离
	TenantIDKey = "tenant_id"

	// OriginTenantIDKey 用户的原始身份租户 ID (身份平面)
	// 无论发生多少次租户切换或跨租户操作，该字段始终记录用户最初登录时的真实身份归属，用于权限判定。
	// 身份与操作目标的不一致（穿透）仅适用于系统租户 (SystemTenantID)，普通租户此字段与 TenantIDKey 保持一致
	OriginTenantIDKey = "origin_tenant_id"

	// UserIDKey 当前登录用户的唯一标识 ID
	UserIDKey = "user_id"

	// SystemTenantID 系统根租户 ID (母体租户)
	SystemTenantID int64 = 1
	// SystemTenantIDStr 字符串格式，用于 Casbin 域等场景
	SystemTenantIDStr = "1"
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
