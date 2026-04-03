package tenant

import "github.com/ecodeclub/ginx"

var (
	ErrUnauthorized     = ginx.Result{Code: 4020401, Msg: "未登录或登录已失效"}
	ErrTenantAccess     = ginx.Result{Code: 4020403, Msg: "您无权操作该租户空间"}
	ErrTenantCreate     = ginx.Result{Code: 4020501, Msg: "创建租户空间失败"}
	ErrTenantList       = ginx.Result{Code: 4020502, Msg: "获取所属租户空间列表失败"}
	ErrTenantSwitch     = ginx.Result{Code: 4020503, Msg: "切换租户上下文失败"}
)
