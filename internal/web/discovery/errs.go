package discovery

import (
	"github.com/Duke1616/eiam/internal/web/user"
	"github.com/ecodeclub/ginx"
)

// 资产发现错误码规范：4060xxx

var (
	ErrUnauthorized    = user.ErrUnauthorized
	ErrUnauthenticated = user.ErrUnauthenticated

	ErrInvalidService  = ginx.Result{Code: 4060001, Msg: "service 字段不能为空"}
	ErrSyncFailed      = ginx.Result{Code: 4060002, Msg: "资产报备失败"}
	ErrInvalidToken    = ginx.Result{Code: 4060003, Msg: "微服务资产上报鉴权失败：无效的通信凭据"}
	ErrServiceMismatch = ginx.Result{Code: 4060004, Msg: "微服务资产上报鉴权失败：通信令牌与上报服务标识不匹配"}
)
