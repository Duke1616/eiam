package errs

import "errors"

var (
	// ErrDatabaseError 数据库通用错误
	ErrDatabaseError = errors.New("数据库错误")

	// ErrRoleCycleInheritance 角色继承存在死循环
	ErrRoleCycleInheritance = errors.New("角色继承存在死循环")
)
