package policy

import "github.com/Duke1616/eiam/internal/web/user"

// 策略中心错误码规范：4050xxx
// 目前主要透传 User 模块的认证错误

var (
	ErrUnauthorized    = user.ErrUnauthorized
	ErrUnauthenticated = user.ErrUnauthenticated
)
