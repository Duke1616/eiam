package errs

import "errors"

var (
	// ErrDatabaseError 数据库通用错误
	ErrDatabaseError = errors.New("数据库错误")
)
