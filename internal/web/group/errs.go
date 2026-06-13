package group

import "github.com/ecodeclub/ginx"

var (
	ErrCreateGroupFailed        = ginx.Result{Code: 4010801, Msg: "创建用户组失败"}
	ErrUpdateGroupFailed        = ginx.Result{Code: 4010802, Msg: "更新用户组信息失败"}
	ErrDeleteGroupFailed        = ginx.Result{Code: 4010803, Msg: "删除用户组失败"}
	ErrListGroupFailed          = ginx.Result{Code: 4010804, Msg: "获取用户组列表失败"}
	ErrGetGroupDetailFailed     = ginx.Result{Code: 4010805, Msg: "获取用户组详情失败"}
	ErrAssignMembersFailed      = ginx.Result{Code: 4010806, Msg: "分配组成员失败"}
	ErrRemoveMembersFailed      = ginx.Result{Code: 4010807, Msg: "移出组成员失败"}
	ErrListGroupMembersFailed   = ginx.Result{Code: 4010808, Msg: "获取组成员列表失败"}
	ErrAssignGroupRoleFailed    = ginx.Result{Code: 4010809, Msg: "用户组授权角色失败"}
	ErrRemoveGroupRoleFailed    = ginx.Result{Code: 4010810, Msg: "用户组解绑角色失败"}
	ErrListGroupRolesFailed     = ginx.Result{Code: 4010811, Msg: "获取用户组绑定角色列表失败"}
	ErrListAttachedGroupsFailed = ginx.Result{Code: 4010812, Msg: "获取附属用户组列表失败"}
)
