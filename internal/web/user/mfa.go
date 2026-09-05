package user

import (
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
)

func (h *Handler) MfaTotpSetup(ctx *ginx.Context, sess session.Session) (ginx.Result, error) {
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

func (h *Handler) MfaTotpBind(ctx *ginx.Context, req MfaTotpBindRequest, sess session.Session) (ginx.Result, error) {
	err := h.userSvc.VerifyAndEnableTOTP(ctx.Request.Context(), sess.Claims().Uid, req.Code, req.Secret)
	if err != nil {
		return ginx.Result{Code: 400, Msg: err.Error()}, nil
	}

	return ginx.Result{Msg: "MFA 开启成功"}, nil
}

func (h *Handler) MfaDisable(ctx *ginx.Context, sess session.Session) (ginx.Result, error) {
	err := h.userSvc.DisableMFA(ctx.Request.Context(), sess.Claims().Uid)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "MFA 已关闭"}, nil
}

func (h *Handler) LoginMFAVerify(ctx *ginx.Context, req MfaLoginVerifyRequest) (ginx.Result, error) {
	result, err := h.coordinator.ResolveMfaChallenge(ctx.Request.Context(), req.MfaToken, req.Code)
	if err != nil {
		return MapLoginError(err), err
	}

	return h.handleLoginResult(ctx, result)
}
