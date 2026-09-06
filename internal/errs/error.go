package errs

import "errors"

var (
	// ErrDatabaseError 数据库通用错误
	ErrDatabaseError = errors.New("数据库错误")

	// ErrRoleCycleInheritance 角色继承存在死循环
	ErrRoleCycleInheritance = errors.New("角色继承存在死循环")

	// ErrRoleSelfInheritance 角色禁止继承自身
	ErrRoleSelfInheritance = errors.New("角色禁止继承自身")

	// 菜单拓扑层级相关错误
	ErrMenuSelfParent  = errors.New("菜单禁止将自身设为父节点")
	ErrMenuCycleParent = errors.New("菜单禁止移入自身的子孙节点（防止循环引用死循环）")

	// 多租户隔离相关错误
	ErrMissingTenantContext = errors.New("多租户安全拦截：未显式声明 IgnoreTenant 且缺失有效租户上下文")

	ErrUserExist          = errors.New("用户名已存在")
	ErrInvalidUser        = errors.New("账号或密码错误")
	ErrProviderNotFound   = errors.New("未找到指定的身份源适配器")
	ErrTenantAccessDenied = errors.New("无权访问该租户空间")

	ErrImmutableInheritance    = errors.New("系统级继承关系严禁移除")
	ErrPasswordWeak            = errors.New("密码强度不符合策略要求")
	ErrUserLocked              = errors.New("账号由于多次输入错误已被锁定，请稍后再试")
	ErrUserNotLinked           = errors.New("外部账号未绑定，请先登录并关联账号")
	ErrExternalBindingRequired = errors.New("该身份源要求绑定现有账号")

	// 邀请治理相关错误
	ErrInvitationNotFound = errors.New("邀请不存在或已过期")
	ErrInvitationFull     = errors.New("邀请次数已达上限")
	ErrAlreadyMember      = errors.New("您已是该租户成员，无需重复加入")
	ErrUnauthorizedHandle = errors.New("无权处理该申请")
	ErrJoinRequestHandled = errors.New("申请已处理")
	ErrApiNotFound        = errors.New("请求的接口未注册或不存在")

	// 策略管理相关错误
	ErrDuplicatePolicyCode = errors.New("策略标识码已存在，请更换后重试或避免与系统预置策略冲突")
	ErrForbidden           = errors.New("越权操作：包含超出当前租户范围的受限权限")
	ErrPolicyInUse         = errors.New("策略正在使用中，请先解除所有关联（用户或角色）后再重试删除")
	ErrDeleteSystemPolicy  = errors.New("系统预置策略禁止删除")

	// 角色管理相关错误
	ErrDeleteSystemRole = errors.New("系统预置角色禁止删除")
	ErrRoleInUse        = errors.New("角色正在使用中，请先解除所有关联（用户或子角色）后再重试删除")
	
	// 个人空间相关错误
	ErrPersonalTenantAdminUnassignForbidden = errors.New("个人空间无法解绑拥有者的 admin 角色")

	// 租户密钥相关错误
	ErrTenantKeyDisabled = errors.New("租户凭证已被禁用")
	ErrInvalidTenantKey  = errors.New("凭证密钥不正确")
	ErrInvalidToken      = errors.New("无效的通信令牌")

	// MFA 多因素认证相关错误
	ErrMfaAttemptsExhausted = errors.New("MFA 验证失败次数过多")
	ErrMfaTokenNotFound     = errors.New("MFA 令牌已过期或无效")

	// 统一身份提供商 (IdP / OAuth2) 相关错误
	ErrOAuthClientNotFound    = errors.New("接入应用不存在或已被移除")
	ErrOAuthClientSecretWrong = errors.New("应用客户端密钥错误")
	ErrInvalidRedirectURI     = errors.New("回调地址不在应用配置的合法白名单中")
	ErrInvalidAuthRequest     = errors.New("授权会话无效或已过期")
)
