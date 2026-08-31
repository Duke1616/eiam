package user

import (
	"errors"

	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
)

func (h *Handler) MfaTotpSetup(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return ErrInternalServer, err
	}

	secret, qrcodeURL, err := h.userSvc.GenerateTOTPSetup(ctx.Request.Context(), sess.Claims().Uid)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{
		Data: MfaTotpSetupResponse{
			Secret:    secret,
			QRCodeURL: qrcodeURL,
		},
	}, nil
}

func (h *Handler) MfaTotpBind(ctx *ginx.Context, req MfaTotpBindRequest) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return ErrInternalServer, err
	}

	err = h.userSvc.VerifyAndEnableTOTP(ctx.Request.Context(), sess.Claims().Uid, req.Code, req.Secret)
	if err != nil {
		return ginx.Result{Code: 400, Msg: err.Error()}, nil
	}

	return ginx.Result{Msg: "MFA 开启成功"}, nil
}

func (h *Handler) MfaDisable(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return ErrInternalServer, err
	}

	err = h.userSvc.DisableMFA(ctx.Request.Context(), sess.Claims().Uid)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "MFA 已关闭"}, nil
}

func (h *Handler) LoginMFAVerify(ctx *ginx.Context, req MfaLoginVerifyRequest) (ginx.Result, error) {
	result, err := h.userSvc.VerifyLoginMFA(ctx.Request.Context(), req.MfaToken, req.Code)
	if err != nil {
		if errors.Is(err, usersvc.ErrMfaAttemptsExhausted) || errors.Is(err, usersvc.ErrMfaTokenNotFound) {
			return ErrMfaTokenInvalid, nil
		}
		return ginx.Result{Code: 401, Msg: err.Error()}, nil
	}

	return h.handleLoginResult(ctx, result)
}
