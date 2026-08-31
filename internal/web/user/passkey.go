package user

import (
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/samber/lo"
)

// PasskeyRegisterStart 获取 Passkey 注册挑战 (Challenge)
func (h *Handler) PasskeyRegisterStart(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return ErrInternalServer, err
	}

	u, err := h.userSvc.GetById(ctx.Request.Context(), sess.Claims().Uid)
	if err != nil {
		return ErrInternalServer, err
	}

	options, sessionData, err := h.passkeySvc.BeginRegistration(ctx.Request.Context(), u)
	if err != nil {
		return ErrInternalServer, err
	}

	token := uuid.New().String()
	err = h.userSvc.SetPasskeyState(ctx.Request.Context(), token, *sessionData)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Data: PasskeyRegisterStartResponse{
		Options: options, SessionToken: token,
	}}, nil
}

// PasskeyRegisterFinish 验证并完成 Passkey 绑定
func (h *Handler) PasskeyRegisterFinish(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return ErrInternalServer, err
	}

	u, err := h.userSvc.GetById(ctx.Request.Context(), sess.Claims().Uid)
	if err != nil {
		return ErrInternalServer, err
	}

	token := ctx.GetHeader("X-Passkey-Session")
	if token == "" {
		return ErrInvalidInput, fmt.Errorf("请求头缺少 X-Passkey-Session")
	}

	sessionData, err := h.userSvc.GetPasskeyState(ctx.Request.Context(), token)
	if err != nil {
		return ErrInternalServer, fmt.Errorf("注册会话已过期或不存在")
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponse(ctx.Request)
	if err != nil {
		return ErrInvalidInput, err
	}

	err = h.passkeySvc.FinishRegistration(ctx.Request.Context(), u, sessionData, parsedResponse)
	if err != nil {
		return ErrUnauthorized, err
	}

	return ginx.Result{Msg: "Passkey 注册成功"}, nil
}

// PasskeyLoginStart 获取 Passkey 登录挑战
func (h *Handler) PasskeyLoginStart(ctx *ginx.Context) (ginx.Result, error) {
	sources, err := h.idsSvc.List(ctx.Request.Context())
	if err != nil {
		return ErrInternalServer, err
	}

	config, found := lo.Find(sources, func(src domain.IdentitySource) bool {
		return src.Type == domain.PASSKEY && src.Enabled
	})
	if !found {
		return ErrInternalServer, fmt.Errorf("Passkey 身份源未启用")
	}

	options, sessionData, err := h.passkeySvc.BeginLogin(ctx.Request.Context(), config)
	if err != nil {
		return ErrInternalServer, err
	}

	token := uuid.New().String()
	err = h.userSvc.SetPasskeyState(ctx.Request.Context(), token, *sessionData)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Data: PasskeyLoginStartResponse{
		Options: options, SessionToken: token,
	}}, nil
}

// PasskeyLoginFinish 验证 Passkey 签名并执行登录
func (h *Handler) PasskeyLoginFinish(ctx *ginx.Context) (ginx.Result, error) {
	token := ctx.GetHeader("X-Passkey-Session")
	if token == "" {
		return ErrInvalidInput, fmt.Errorf("请求头缺少 X-Passkey-Session")
	}

	sessionData, err := h.userSvc.GetPasskeyState(ctx.Request.Context(), token)
	if err != nil {
		return ErrInternalServer, fmt.Errorf("登录会话已过期或不存在")
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(ctx.Request)
	if err != nil {
		return ErrInvalidInput, err
	}

	u, err := h.passkeySvc.FinishLogin(ctx.Request.Context(), sessionData, parsedResponse)
	if err != nil {
		return ErrUnauthorized, err
	}

	result, err := h.userSvc.LoginWithoutPassword(ctx.Request.Context(), u.ID, false)
	if err != nil {
		return ErrInternalServer, err
	}

	return h.handleLoginResult(ctx, result)
}
