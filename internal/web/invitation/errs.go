package invitation

import "github.com/ecodeclub/ginx"

var (
	ErrInvitationCreateFailed = ginx.Result{Code: 4010701, Msg: "创建邀请码失败"}
	ErrInvitationListFailed   = ginx.Result{Code: 4010702, Msg: "获取邀请列表失败"}
	ErrInvitationRevokeFailed = ginx.Result{Code: 4010703, Msg: "撤回邀请链接失败"}
	ErrInvitationVerifyFailed = ginx.Result{Code: 4010704, Msg: "校验邀请码失败"}
	ErrInvitationAcceptFailed = ginx.Result{Code: 4010705, Msg: "接受邀请失败"}
	ErrJoinRequestListFailed  = ginx.Result{Code: 4010706, Msg: "获取审批列表失败"}
	ErrJoinRequestHandleFailed = ginx.Result{Code: 4010707, Msg: "处理入驻申请失败"}

	ErrInvitationNotFound = ginx.Result{Code: 4030701, Msg: "邀请链接不存在或已过期"}
	ErrInvitationFull     = ginx.Result{Code: 4030702, Msg: "邀请码使用次数已达上限"}
	ErrAlreadyMember      = ginx.Result{Code: 4030703, Msg: "您已是该租户成员，无需重复加入"}
	ErrUnauthorized       = ginx.Result{Code: 4030704, Msg: "无权处理该申请"}
	ErrJoinRequestHandled = ginx.Result{Code: 4030705, Msg: "申请已处理，请勿重复操作"}
)
