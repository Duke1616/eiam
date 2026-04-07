package role

import "github.com/ecodeclub/ginx"

var (
	// ErrRoleCreateFailed 创建逻辑错误
	ErrRoleCreateFailed = ginx.Result{Code: 4030901, Msg: "创建角色失败"}
	ErrRoleUpdateFailed = ginx.Result{Code: 4030902, Msg: "更新角色失败"}
	ErrRoleListFailed   = ginx.Result{Code: 4030903, Msg: "获取角色列表失败"}
	ErrRoleAssignFailed = ginx.Result{Code: 4030904, Msg: "分配角色失败"}
	ErrGetMyRolesFailed = ginx.Result{Code: 4030905, Msg: "获取当前有效角色失败"}

	// ErrRoleNotFound 资源类错误
	ErrRoleNotFound = ginx.Result{Code: 4030501, Msg: "该角色标识不存在"}
)
