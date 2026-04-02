package ctxutil

import (
	"context"
)

type contextKey string

const (
	tenantIDKey contextKey = "tenant_id"
	userIDKey   contextKey = "user_id"
)

// WithTenantID 将租户 ID 注入 context
func WithTenantID(ctx context.Context, tenantID int64) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

// GetTenantID 从 context 中安全提取租户 ID
func GetTenantID(ctx context.Context) int64 {
	if ctx == nil {
		return 0
	}
	if id, ok := ctx.Value(tenantIDKey).(int64); ok {
		return id
	}
	return 0
}

// WithUserID 将用户 ID 注入 context
func WithUserID(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// GetUserID 从 context 中获取当前操作的用户 ID
func GetUserID(ctx context.Context) int64 {
	if ctx == nil {
		return 0
	}
	if id, ok := ctx.Value(userIDKey).(int64); ok {
		return id
	}
	return 0
}
