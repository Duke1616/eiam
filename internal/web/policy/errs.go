package policy

import (
	"github.com/Duke1616/eiam/internal/web/user"
	"github.com/ecodeclub/ginx"
)

// 策略中心错误码规范：4050xxx
// 目前主要透传 User 模块的认证错误

var (
	ErrUnauthorized    = user.ErrUnauthorized
	ErrUnauthenticated = user.ErrUnauthenticated

	ErrInvalidUserId     = ginx.Result{Code: 4050001, Msg: "用户 ID 非法"}
	ErrGetUserFailed     = ginx.Result{Code: 4050002, Msg: "获取用户信息失败"}
	ErrGetAttachedFailed = ginx.Result{Code: 4050003, Msg: "获取关联策略失败"}
)
