package identity_source

import "github.com/ecodeclub/ginx"

var (
	ErrIdentitySourceSaveFailed           = ginx.Result{Code: 4010601, Msg: "保存身份源失败"}
	ErrIdentitySourceListFailed           = ginx.Result{Code: 4010602, Msg: "获取身份源列表失败"}
	ErrIdentitySourceDeleteFailed         = ginx.Result{Code: 4010603, Msg: "删除身份源失败"}
	ErrIdentitySourceTestConnectionFailed = ginx.Result{Code: 4010604, Msg: "身份源连接测试失败"}
	ErrIdentitySourceInvalidId            = ginx.Result{Code: 4010605, Msg: "身份源 ID 非法"}
)
