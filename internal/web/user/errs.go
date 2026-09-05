package user

import (
	"errors"

	"github.com/Duke1616/eiam/internal/errs"
	"github.com/ecodeclub/ginx"
)

// 业务语义码规范：[分类 1位: 4] + [模块 3位: 010 (用户/认证)] + [细分类别 1位] + [具体错误 2位]
var (
	// 40101xx: 参数与凭据格式校验类错误
	ErrInvalidInput       = ginx.Result{Code: 4010100, Msg: "参数解析失败"}
	ErrMissingCredential  = ginx.Result{Code: 4010101, Msg: "缺少必要的认证凭据"}

	// 40102xx: 基础密码与本地账号凭据核验类错误
	ErrPasswordMismatch   = ginx.Result{Code: 4010201, Msg: "两次输入的密码不一致"}
	ErrUnauthorized       = ginx.Result{Code: 4010202, Msg: "认证失败 (账号或密码错误)"}
	ErrUserLocked         = ginx.Result{Code: 4010203, Msg: "账号由于多次输入错误已被锁定，请稍后再试"}
	ErrUserDisabled       = ginx.Result{Code: 4010204, Msg: "账号已被停用，请联系企业管理员"}
	ErrPasswordWeak       = ginx.Result{Code: 4010205, Msg: "密码强度不符合安全策略要求"}
	ErrPasswordExpired    = ginx.Result{Code: 4010206, Msg: "凭据已过期，请先修改密码"}

	// 40103xx: 第三方与联合身份 (OIDC / OAuth / 外部联邦) 错误
	ErrOIDCDenied         = ginx.Result{Code: 4010301, Msg: "OIDC 外部授权被拒绝"}
	ErrUserNotLinked      = ginx.Result{Code: 4010302, Msg: "外部身份未绑定，请先登录现有账号完成关联"}
	ErrExternalBindingReq = ginx.Result{Code: 4010303, Msg: "该身份源要求绑定现有账号"}
	ErrBindFailed         = ginx.Result{Code: 4010304, Msg: "外部身份绑定失败，令牌可能已失效"}

	// 40104xx: 多因素认证 (MFA) 与无密强认证 (Passkey) 错误
	ErrUnauthenticated    = ginx.Result{Code: 4010401, Msg: "请先完成主体账号身份核验"}
	ErrSessionInvalid     = ginx.Result{Code: 4010402, Msg: "会话失效，请重新登录"}
	ErrMfaTokenInvalid    = ginx.Result{Code: 4010403, Msg: "MFA 二次验证令牌已过期或失效"}
	ErrMfaCodeInvalid     = ginx.Result{Code: 4010404, Msg: "动态验证码错误，请重新输入"}
	ErrMfaExhausted       = ginx.Result{Code: 4010405, Msg: "验证失败次数过多，令牌已被作废，请重新登录"}
	ErrPasskeyExpired     = ginx.Result{Code: 4010406, Msg: "Passkey 认证挑战已过期，请刷新重试"}
	ErrPasskeyVerifyFail  = ginx.Result{Code: 4010407, Msg: "Passkey 凭据签名核验失败"}

	// 40105xx: 租户空间准入与切换错误
	ErrUserNotFound       = ginx.Result{Code: 4010501, Msg: "未找到该用户信息"}
	ErrTenantAccessDenied = ginx.Result{Code: 4010502, Msg: "无权访问目标租户空间"}

	// 40109xx: 系统服务架构与依赖组件链路错误
	ErrInternalServer     = ginx.Result{Code: 4010901, Msg: "服务内部链路繁忙"}
	ErrSignupFailed       = ginx.Result{Code: 4010902, Msg: "账户注册失败"}
	ErrProviderMissing    = ginx.Result{Code: 4010903, Msg: "不适用的认证源适配器"}
	ErrUserListFailed     = ginx.Result{Code: 4010904, Msg: "获取用户列表失败"}
	ErrUserUpdateFailed   = ginx.Result{Code: 4010905, Msg: "更新用户信息失败"}
	ErrUserDeleteFailed   = ginx.Result{Code: 4010906, Msg: "删除用户失败"}
	ErrLdapSearchFailed   = ginx.Result{Code: 4010907, Msg: "搜索 LDAP 用户失败"}
	ErrLdapSyncFailed     = ginx.Result{Code: 4010908, Msg: "同步 LDAP 用户失败"}
	ErrLdapRefreshFailed  = ginx.Result{Code: 4010909, Msg: "刷新 LDAP 缓存失败"}
)

// MapLoginError 将底层 Service/Coordinator 抛出的领域哨兵错误转换为富语义的 ginx.Result
func MapLoginError(err error) ginx.Result {
	if err == nil {
		return ginx.Result{}
	}
	switch {
	case errors.Is(err, errs.ErrUserLocked):
		return ErrUserLocked
	case errors.Is(err, errs.ErrInvalidUser):
		return ErrUnauthorized
	case errors.Is(err, errs.ErrUserNotLinked):
		return ErrUserNotLinked
	case errors.Is(err, errs.ErrMfaAttemptsExhausted):
		return ErrMfaExhausted
	case errors.Is(err, errs.ErrMfaTokenNotFound):
		return ErrMfaTokenInvalid
	case errors.Is(err, errs.ErrPasswordWeak):
		return ErrPasswordWeak
	case errors.Is(err, errs.ErrTenantAccessDenied):
		return ErrTenantAccessDenied
	default:
		return ErrUnauthorized
	}
}

