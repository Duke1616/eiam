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

	ErrInvalidPolicyCode = ginx.Result{Code: 4050004, Msg: "策略标识非法"}
	ErrGetPolicyFailed   = ginx.Result{Code: 4050005, Msg: "获取策略信息失败"}
	ErrGetSummaryFailed  = ginx.Result{Code: 4050006, Msg: "获取摘要分析失败"}

	ErrCreatePolicyFailed      = ginx.Result{Code: 4050007, Msg: "创建策略失败"}
	ErrUpdatePolicyFailed      = ginx.Result{Code: 4050008, Msg: "更新策略失败"}
	ErrListPolicyFailed        = ginx.Result{Code: 4050009, Msg: "查询策略列表失败"}
	ErrAttachPolicyFailed      = ginx.Result{Code: 4050010, Msg: "绑定策略失败"}
	ErrDetachPolicyFailed      = ginx.Result{Code: 4050011, Msg: "解绑策略失败"}
	ErrBatchAttachPolicyFailed = ginx.Result{Code: 4050012, Msg: "批量绑定策略失败"}
	ErrDuplicatePolicyCode     = ginx.Result{Code: 4050013, Msg: "策略标识码已存在(请勿与系统级策略冲突)"}
)
