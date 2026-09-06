package grant

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/service/permission"
)

type authCodeGrantHandler struct {
	userRepo repository.IUserRepository
	permSvc  permission.IPermissionService
	cache    cache.IOidcCache
	signer   IKeySigner
	secLogFn func(ctx context.Context, client domain.OAuthClient, action, failReason string)
}

// NewAuthCodeGrantHandler 构造授权码换发 Token 策略实例
func NewAuthCodeGrantHandler(
	userRepo repository.IUserRepository,
	permSvc permission.IPermissionService,
	cache cache.IOidcCache,
	signer IKeySigner,
	secLogFn func(ctx context.Context, client domain.OAuthClient, action, failReason string),
) IGrantHandler {
	return &authCodeGrantHandler{
		userRepo: userRepo,
		permSvc:  permSvc,
		cache:    cache,
		signer:   signer,
		secLogFn: secLogFn,
	}
}

func (h *authCodeGrantHandler) GrantType() string {
	return "authorization_code"
}

func (h *authCodeGrantHandler) Handle(ctx context.Context, req domain.TokenRequest, client domain.OAuthClient, issuerURL string) (*domain.OidcTokenResult, error) {
	if req.Code == "" {
		return nil, fmt.Errorf("缺少 code 参数")
	}

	// 1. 原子读取并销毁授权码 (GETDEL)，防止重放攻击
	data, err := h.cache.GetAndDelAuthCodeContext(ctx, req.Code)
	if err != nil || len(data) == 0 {
		if h.secLogFn != nil {
			h.secLogFn(ctx, client, "replay_attack_detected", fmt.Sprintf("尝试重放已失效授权码: %s", req.Code))
		}
		return nil, fmt.Errorf("授权码已失效或已被使用 (防重放拦截)")
	}

	var authCode domain.AuthCode
	if err = json.Unmarshal(data, &authCode); err != nil {
		return nil, fmt.Errorf("反序列化授权码上下文失败: %w", err)
	}

	if authCode.IsExpired(5 * time.Minute) {
		return nil, fmt.Errorf("授权码已超时")
	}

	if authCode.ClientID != client.ClientID {
		return nil, fmt.Errorf("客户端标识与授权码不匹配")
	}

	// 2. 校验回调地址一致性
	if req.RedirectURI != "" && authCode.RedirectURI != req.RedirectURI {
		return nil, fmt.Errorf("重定向地址与授权发起时不一致")
	}

	// 3. 校验客户端凭证或 PKCE 挑战码
	if authCode.CodeChallenge != "" {
		if !client.VerifyPKCE(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, fmt.Errorf("PKCE code_verifier 校验失败")
		}
	} else if !client.VerifySecret(req.ClientSecret) {
		return nil, errs.ErrOAuthClientSecretWrong
	}

	// 4. 获取授权码绑定租户下的用户角色与名片信息
	roles, profile := FetchUserClaims(ctx, authCode.TenantID, authCode.UserID, authCode.Username, h.permSvc, h.userRepo)

	// 5. 统一签发 AccessToken 与 IDToken
	accessToken, idToken, err := IssueTokenPair(h.signer, TokenPayload{
		IssuerURL: issuerURL,
		ClientID:  client.ClientID,
		UserID:    authCode.UserID,
		Username:  authCode.Username,
		TenantID:  authCode.TenantID,
		Profile:   profile,
		Roles:     roles,
		Nonce:     authCode.Nonce,
	})
	if err != nil {
		return nil, err
	}

	// 6. 若应用开通 refresh_token 权限，签发 RefreshToken 并记录会话
	var refreshToken string
	if client.IsGrantTypeAllowed("refresh_token") {
		refreshToken, err = GenerateRandomString(32)
		if err == nil {
			session := domain.RefreshTokenSession{
				RefreshToken: refreshToken,
				ClientID:     client.ClientID,
				UserID:       authCode.UserID,
				Username:     authCode.Username,
				TenantID:     authCode.TenantID,
				Scopes:       authCode.Scopes,
				CreatedAt:    time.Now().Unix(),
			}
			sessBytes, _ := json.Marshal(session)
			_ = h.cache.SaveRefreshToken(ctx, refreshToken, sessBytes)
			_ = h.cache.TrackUserRefreshToken(ctx, strconv.FormatInt(authCode.UserID, 10), refreshToken)
		}
	}

	return &domain.OidcTokenResult{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    7200,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		Scope:        strings.Join(authCode.Scopes, " "),
	}, nil
}
