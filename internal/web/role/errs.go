package role

import (
	"github.com/Duke1616/eiam/internal/web/user"
	"github.com/ecodeclub/ginx"
)

var (
	// ErrRoleCreateFailed 创建逻辑错误
	ErrRoleCreateFailed = ginx.Result{Code: 4010501, Msg: "创建角色失败"}
	ErrRoleUpdateFailed = ginx.Result{Code: 4010502, Msg: "更新角色失败"}
	ErrRoleListFailed   = ginx.Result{Code: 4010503, Msg: "获取角色列表失败"}
	ErrRoleDeleteFailed = ginx.Result{Code: 4010504, Msg: "删除角色失败"}
	ErrRoleAssignFailed = ginx.Result{Code: 4030904, Msg: "分配角色失败"}
	ErrGetMyRolesFailed = ginx.Result{Code: 4030905, Msg: "获取当前有效角色失败"}

	// ErrRoleNotFound 资源类错误
	ErrRoleNotFound = ginx.Result{Code: 4030501, Msg: "该角色标识不存在"}

	ErrUnauthenticated = user.ErrUnauthenticated
)
