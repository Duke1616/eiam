package user

import (
	"fmt"
	"strconv"

	"github.com/Duke1616/eiam/internal/domain"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gotomicro/ego/core/elog"
)

func (h *Handler) Signup(ctx *ginx.Context, req SignupRequest) (ginx.Result, error) {
	if req.Password != req.ConfirmPassword {
		return ErrPasswordMismatch, nil
	}

	id, err := h.userSvc.Signup(ctx.Request.Context(), req.ToDomain())
	if err != nil {
		return ErrSignupFailed, err
	}

	return ginx.Result{
		Data: id,
		Msg:  "注册成功",
	}, nil
}

func (h *Handler) LoginLdap(ctx *ginx.Context, req LoginRequest) (ginx.Result, error) {
	return h.executeLogin(ctx, domain.LDAP.String(), req.Username, req.Password)
}

func (h *Handler) LoginSystem(ctx *ginx.Context, req LoginRequest) (ginx.Result, error) {
	return h.executeLogin(ctx, domain.LOCAL.String(), req.Username, req.Password)
}

func (h *Handler) executeLogin(ctx *ginx.Context, provider, username, password string) (ginx.Result, error) {
	result, err := h.coordinator.Authenticate(ctx.Request.Context(), provider, usersvc.PasswordCredential{
		Username: username,
		Password: password,
	})
	if err != nil {
		return MapLoginError(err), err
	}

	return h.handleLoginResult(ctx, result)
}

func (h *Handler) BindConfirm(ctx *ginx.Context, req BindConfirmRequest) (ginx.Result, error) {
	result, err := h.coordinator.Authenticate(ctx.Request.Context(), domain.LOCAL.String(), usersvc.PasswordCredential{
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		return MapLoginError(err), err
	}

	err = h.userSvc.ConsumeBindToken(ctx.Request.Context(), result.User.ID, req.BindToken)
	if err != nil {
		return ErrBindFailed, err
	}

	h.logger.Info("用户显式确认并自动完成第三方身份绑定", elog.Int64("uid", result.User.ID))
	return h.handleLoginResult(ctx, result)
}

func (h *Handler) handleLoginResult(ctx *ginx.Context, result domain.LoginResult) (ginx.Result, error) {
	if result.MfaRequired {
		return ginx.Result{
			Msg: "请进行二次验证",
			Data: RetrieveUser{
				User:            ToUserVO(result.User),
				MfaRequired:     true,
				MfaToken:        result.MfaToken,
				CurrentTenantID: result.TenantID,
			},
		}, nil
	}

	if err := h.issueSession(ctx, result.User.ID, result.User.Username, result.TenantID); err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{
		Msg: fmt.Sprintf("登录成功，欢迎回来：%s", result.User.Username),
		Data: RetrieveUser{
			User:             ToUserVO(result.User),
			Tenants:          ToTenantVOs(result.Tenants),
			CurrentTenantID:  result.TenantID,
			MustSelectTenant: result.MustSelectTenant,
			MustBind:         result.MustBind,
			BindToken:        result.BindToken,
		},
	}, nil
}

func (h *Handler) issueSession(ctx *ginx.Context, uid int64, username string, tenantID int64) error {
	_, err := session.NewSessionBuilder(ctx, uid).
		SetJwtData(map[string]string{
			"tenant_id": strconv.FormatInt(tenantID, 10),
			"username":  username,
		}).
		SetSessData(map[string]any{
			"username":  username,
			"tenant_id": tenantID,
		}).
		Build()

	return err
}

func (h *Handler) Logout(ctx *ginx.Context, sess session.Session) (ginx.Result, error) {
	claims := sess.Claims()
	uid := claims.Uid
	username, _ := claims.Get("username").AsString()
	tid, _ := claims.Get("tenant_id").AsInt64()

	if err := sess.Destroy(ctx.Context); err != nil {
		return ErrInternalServer, err
	}

	h.coordinator.RecordLogout(ctx.Request.Context(), uid, tid, username)
	return ginx.Result{Msg: "退出登录成功"}, nil
}
