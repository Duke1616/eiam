package audit

import "github.com/ecodeclub/ginx"

var (
	ErrListAuthLogsFailed      = ginx.Result{Code: 4011201, Msg: "查询认证审计日志失败"}
	ErrListOperationLogsFailed = ginx.Result{Code: 4011202, Msg: "查询操作审计日志失败"}
)
