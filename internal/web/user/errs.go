package user

import "github.com/ecodeclub/ginx"

// 业务语义码规范：[分类 1位] + [服务 3位] + [具体错误 3位]
// 用户模块前缀: 4010xxx (示例)
var (
	// ErrInvalidInput 输入参数校验失败
	ErrInvalidInput = ginx.Result{Code: 4010100, Msg: "参数解析失败"}

	// ErrPasswordMismatch 账号密码逻辑错误
	ErrPasswordMismatch = ginx.Result{Code: 4010201, Msg: "两次输入的密码不一致"}
	ErrUnauthorized     = ginx.Result{Code: 4010202, Msg: "认证失败 (账号或密码错误)"}

	// ErrUnauthenticated 权限/安全类错误
	ErrUnauthenticated = ginx.Result{Code: 4010401, Msg: "请先登录主体账号"}
	ErrSessionInvalid  = ginx.Result{Code: 4010402, Msg: "会话失效，请重新登录"}

	// ErrUserNotFound 资源类错误
	ErrUserNotFound = ginx.Result{Code: 4010501, Msg: "未找到该用户信息"}

	// ErrInternalServer 系统架构类错误
	ErrInternalServer  = ginx.Result{Code: 4010901, Msg: "服务内部链路繁忙"}
	ErrSignupFailed    = ginx.Result{Code: 4010902, Msg: "账户预配 JIT 失败"}
	ErrProviderMissing = ginx.Result{Code: 4010903, Msg: "不适用的认证源适配器"}
)
