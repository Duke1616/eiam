package permission

import "github.com/ecodeclub/ginx"

var (
	ErrInternalServer         = ginx.Result{Code: 504000, Msg: "系统内部错误"}
	ErrPermissionCreateFailed = ginx.Result{Code: 504001, Msg: "权限创建失败"}
	ErrBindFailed             = ginx.Result{Code: 504002, Msg: "资源绑定失败"}
	ErrAssignRoleFailed       = ginx.Result{Code: 504003, Msg: "分配角色失败"}
	ErrAuthMenuFailed         = ginx.Result{Code: 504004, Msg: "获取授权菜单失败"}
)
