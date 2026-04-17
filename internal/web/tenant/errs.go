package tenant

import (
	"github.com/Duke1616/eiam/internal/web/user"
	"github.com/ecodeclub/ginx"
)

var (
	// ErrUnauthorized 认证状态相关
	ErrUnauthorized = ginx.Result{Code: 4020401, Msg: "未登录或登录会话已失效"}
	ErrTenantAccess = ginx.Result{Code: 4020403, Msg: "您无权在该租户空间内执行此操作"}

	// ErrTenantCreate 系统处理类错误
	ErrTenantCreate = ginx.Result{Code: 4020901, Msg: "创建租户空间失败"}
	ErrTenantList   = ginx.Result{Code: 4020902, Msg: "批量检索租户空间失败"}
	ErrTenantSwitch = ginx.Result{Code: 4020903, Msg: "该目标租户上下文不可用"}
	ErrTenantUpdate = ginx.Result{Code: 4020904, Msg: "更新租户空间信息失败"}
	ErrTenantDelete = ginx.Result{Code: 4020905, Msg: "删除租户空间失败"}
	ErrTenantGet    = ginx.Result{Code: 4020906, Msg: "获取租户空间详情失败"}

	ErrUnauthenticated = user.ErrUnauthenticated
)
