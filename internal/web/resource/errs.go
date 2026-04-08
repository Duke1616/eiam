package resource

import "github.com/ecodeclub/ginx"

// 资源管理模块前缀: 4060xxx
var (
	// ErrSyncFailed 资产同步由于业务逻辑或持久化层失败
	ErrSyncFailed = ginx.Result{Code: 4060901, Msg: "同步资产上报数据失败"}
)
