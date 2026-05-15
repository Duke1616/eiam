package discovery

import (
	"github.com/Duke1616/eiam/internal/web/user"
	"github.com/ecodeclub/ginx"
)

// 资产发现错误码规范：4060xxx

var (
	ErrUnauthorized    = user.ErrUnauthorized
	ErrUnauthenticated = user.ErrUnauthenticated

	ErrInvalidService = ginx.Result{Code: 4060001, Msg: "service 字段不能为空"}
	ErrSyncFailed     = ginx.Result{Code: 4060002, Msg: "资产报备失败"}
)
