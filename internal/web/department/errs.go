package department

import "github.com/ecodeclub/ginx"

var (
	ErrCreateDeptFailed      = ginx.Result{Code: 4010701, Msg: "创建部门失败"}
	ErrUpdateDeptFailed      = ginx.Result{Code: 4010702, Msg: "更新部门失败"}
	ErrDeleteDeptFailed      = ginx.Result{Code: 4010703, Msg: "删除部门失败"}
	ErrListDeptFailed        = ginx.Result{Code: 4010704, Msg: "获取部门列表失败"}
	ErrGetDeptDetailFailed   = ginx.Result{Code: 4010705, Msg: "获取部门详情失败"}
	ErrAssignUsersFailed     = ginx.Result{Code: 4010706, Msg: "分配用户到部门失败"}
	ErrRemoveUsersFailed     = ginx.Result{Code: 4010707, Msg: "移出部门用户失败"}
	ErrListDeptMembersFailed = ginx.Result{Code: 4010708, Msg: "获取部门成员列表失败"}
)
