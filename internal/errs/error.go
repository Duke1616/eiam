package errs

import "errors"

var (
	// ErrDatabaseError 数据库通用错误
	ErrDatabaseError = errors.New("数据库错误")

	// ErrRoleCycleInheritance 角色继承存在死循环
	ErrRoleCycleInheritance = errors.New("角色继承存在死循环")

	ErrUserExist          = errors.New("用户名已存在")
	ErrInvalidUser        = errors.New("账号或密码错误")
	ErrProviderNotFound   = errors.New("未找到指定的身份源适配器")
	ErrTenantAccessDenied = errors.New("无权访问该租户空间")

	ErrImmutableInheritance = errors.New("系统级继承关系严禁移除")
)
