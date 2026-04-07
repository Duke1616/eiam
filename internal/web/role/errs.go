package role

import "github.com/ecodeclub/ginx"

var (
	ErrRoleCreateFailed = ginx.Result{Code: 505001, Msg: "创建角色失败"}
	ErrRoleUpdateFailed = ginx.Result{Code: 505002, Msg: "更新角色失败"}
	ErrRoleListFailed   = ginx.Result{Code: 505003, Msg: "获取角色列表失败"}
	ErrRoleNotFound     = ginx.Result{Code: 505004, Msg: "角色未找到"}
	ErrRoleAssignFailed = ginx.Result{Code: 505005, Msg: "分配角色失败"}
	ErrGetMyRolesFailed = ginx.Result{Code: 505006, Msg: "获取当前角色失败"}
	ErrUnauthorized     = ginx.Result{Code: 505007, Msg: "未登录或会话失效"}
	ErrUnauthenticated  = ginx.Result{Code: 4010401, Msg: "请先登录主体账号"}
)
