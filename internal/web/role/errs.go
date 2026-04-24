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

	ErrRoleNotFound = ginx.Result{Code: 4030501, Msg: "该角色标识不存在"}

	ErrInvalidUserId         = ginx.Result{Code: 4010505, Msg: "用户 ID 非法"}
	ErrGetUserFailed         = ginx.Result{Code: 4010506, Msg: "获取用户信息失败"}
	ErrGetUserRoleCodeFailed = ginx.Result{Code: 4010507, Msg: "获取用户角色代码失败"}
	ErrGetRoleDetailFailed   = ginx.Result{Code: 4010508, Msg: "获取角色详情失败"}
	ErrGetRoleAnalysisFailed = ginx.Result{Code: 4010509, Msg: "获取角色权限分析失败"}
	ErrImmutableInheritance  = ginx.Result{Code: 4010510, Msg: "系统级继承关系严禁移除"}
	ErrRoleSelfInheritance   = ginx.Result{Code: 4010511, Msg: "角色禁止继承自身"}
	ErrRoleCycleInheritance  = ginx.Result{Code: 4010512, Msg: "角色继承存在死循环"}

	ErrUnauthenticated = user.ErrUnauthenticated
)
