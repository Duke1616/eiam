package idp

import "github.com/ecodeclub/ginx"

var (
	ErrIdpClientCreateFailed = ginx.Result{Code: 4010701, Msg: "创建接入应用失败"}
	ErrIdpClientUpdateFailed = ginx.Result{Code: 4010702, Msg: "更新接入应用失败"}
	ErrIdpClientDeleteFailed = ginx.Result{Code: 4010703, Msg: "删除接入应用失败"}
	ErrIdpClientResetFailed  = ginx.Result{Code: 4010704, Msg: "重置应用密钥失败"}
	ErrIdpClientListFailed   = ginx.Result{Code: 4010705, Msg: "获取应用列表失败"}
	ErrIdpClientInvalidID    = ginx.Result{Code: 4010706, Msg: "非法的应用 ID"}
	ErrIdpAuthCompleteFailed = ginx.Result{Code: 4010707, Msg: "确认 OIDC 授权失败"}
)
