package errs

import "errors"

var (
	// ErrDatabaseError 数据库通用错误
	ErrDatabaseError = errors.New("数据库错误")

	// ErrRoleCycleInheritance 角色继承存在死循环
	ErrRoleCycleInheritance = errors.New("角色继承存在死循环")

	// ErrRoleSelfInheritance 角色禁止继承自身
	ErrRoleSelfInheritance = errors.New("角色禁止继承自身")

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
)
