package user

import (
	"errors"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gotomicro/ego/core/elog"
	"github.com/samber/lo"
)

// OIDCAuthURL 引导用户重定向至 OIDC 提供商 (如飞书)
func (h *Handler) OIDCAuthURL(ctx *ginx.Context) (ginx.Result, error) {
	providerType, err := ctx.Query("provider_type").AsString()
	if err != nil || providerType == "" {
		return ErrInvalidInput, fmt.Errorf("provider_type 不能为空")
	}

	// 读取可选的业务重定向深度路径或邀请码（完全向后兼容）
	redirectURL, _ := ctx.Query("redirect").AsString()
	inviteCode, _ := ctx.Query("invite_code").AsString()

	h.logger.Info("[OIDC] 获取授权 URL",
		elog.String("provider_type", providerType),
		elog.String("redirect", redirectURL),
	)

	sctx := domain.OAuthStateContext{
		RedirectURL: redirectURL,
		InviteCode:  inviteCode,
	}

	url, err := h.idsSvc.GetAuthURLWithContext(ctx.Request.Context(), providerType, sctx)
	if err != nil {
		h.logger.Error("[OIDC] 获取授权 URL 失败", elog.FieldErr(err))
		return ErrInternalServer, err
	}

	h.logger.Info("[OIDC] 授权 URL 生成成功", elog.String("url", url))
	return ginx.Result{Data: url}, nil
}

// OIDCCallback 处理 OIDC 授权码回调
func (h *Handler) OIDCCallback(ctx *ginx.Context) (ginx.Result, error) {
	if errParam, _ := ctx.Query("error").AsString(); errParam != "" {
		desc, _ := ctx.Query("error_description").AsString()
		h.logger.Warn("[OIDC] 授权被拒绝", elog.String("error", errParam), elog.String("desc", desc))
		return ErrOIDCDenied, fmt.Errorf("OIDC 授权被拒绝: %s - %s", errParam, desc)
	}

	code, _ := ctx.Query("code").AsString()
	state, _ := ctx.Query("state").AsString()

	if code == "" || state == "" {
		return ErrInvalidInput, fmt.Errorf("OIDC 回调缺少必要参数: code 或 state 为空")
	}

	h.logger.Info("[OIDC] 收到回调", elog.Int("code_len", len(code)), elog.String("state", state))

	ident, sctx, err := h.idsSvc.VerifyOIDCWithContext(ctx.Request.Context(), state, code)
	if err != nil {
		h.logger.Error("[OIDC] 身份校验失败", elog.FieldErr(err))
		return ErrOIDCDenied, err
	}

	h.logger.Info("[OIDC] 身份校验成功",
		elog.String("provider", ident.Provider),
		elog.String("external_id", ident.ExternalID),
		elog.String("username", ident.Username),
		elog.String("redirect_url", sctx.RedirectURL),
	)

	result, err := h.coordinator.Authenticate(ctx.Request.Context(), domain.OIDC.String(), ident)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotLinked) {
			token, tokenErr := h.userSvc.GenerateBindToken(ctx.Request.Context(), ident)
			if tokenErr != nil {
				return ErrInternalServer, tokenErr
			}
			return ginx.Result{
				Code: 0,
				Msg:  "请先登录现有账号完成绑定",
				Data: RetrieveUser{
					MustBind:    true,
					BindToken:   token,
					RedirectURL: sctx.RedirectURL,
				},
			}, nil
		}
		h.logger.Error("[OIDC] 登录处理失败", elog.FieldErr(err))
		return MapLoginError(err), err
	}

	loginRes, loginErr := h.handleLoginResult(ctx, result)
	if loginErr != nil {
		return loginRes, loginErr
	}

	// 注入透传的原始跳转深度 URL
	if ru, ok := loginRes.Data.(RetrieveUser); ok && sctx.RedirectURL != "" {
		ru.RedirectURL = sctx.RedirectURL
		loginRes.Data = ru
	}

	return loginRes, nil
}

func (h *Handler) BindIdentity(ctx *ginx.Context, req BindIdentityRequest) (ginx.Result, error) {
	err := h.userSvc.BindIdentity(ctx.Request.Context(), req.UserID, req.ToDomain())
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "绑定身份成功"}, nil
}

func (h *Handler) UnbindIdentity(ctx *ginx.Context, req UnbindIdentityRequest) (ginx.Result, error) {
	err := h.userSvc.UnbindIdentity(ctx.Request.Context(), req.UserID, req.Provider, req.IdentityID)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "解除绑定成功"}, nil
}

func (h *Handler) ManageIdentities(ctx *ginx.Context, req ManageIdentitiesRequest) (ginx.Result, error) {
	identities := []domain.UserIdentity{
		{Provider: "ldap", LdapInfo: domain.LdapInfo(req.LdapInfo)},
		{Provider: "wechat", WechatInfo: domain.WechatInfo(req.WechatInfo)},
		{Provider: "feishu", FeishuInfo: domain.FeishuInfo(req.FeishuInfo)},
	}

	err := h.userSvc.ManageIdentities(ctx.Request.Context(), req.UserID, identities)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "外部身份治理信息已更新"}, nil
}

// ListMyIdentities 获取当前用户绑定的身份列表 (支持按 provider 过滤)
func (h *Handler) ListMyIdentities(ctx *ginx.Context, sess session.Session) (ginx.Result, error) {
	provider, _ := ctx.Query("provider").AsString()
	uis, err := h.userSvc.ListIdentitiesByUserID(ctx.Request.Context(), sess.Claims().Uid, provider)
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{
		Data: lo.Map(uis, func(id domain.UserIdentity, _ int) IdentityVo {
			return IdentityVo{
				Provider:   id.Provider,
				IdentityID: id.IdentityID,
				PasskeyInfo: PasskeyInfo{
					SignCount:      id.PasskeyInfo.SignCount,
					BackupEligible: id.PasskeyInfo.BackupEligible,
					BackupState:    id.PasskeyInfo.BackupState,
					Nickname:       id.PasskeyInfo.Nickname,
				},
			}
		}),
	}, nil
}
