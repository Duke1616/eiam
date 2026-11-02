package grant

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type clientCredentialsGrantHandler struct {
	signer   IKeySigner
	secLogFn func(ctx context.Context, app domain.Application, action, failReason string)
}

// NewClientCredentialsGrantHandler 构造客户端凭据模式授权策略 (RFC 6749 Section 4.4 M2M)
func NewClientCredentialsGrantHandler(
	signer IKeySigner,
	secLogFn func(ctx context.Context, app domain.Application, action, failReason string),
) IGrantHandler {
	return &clientCredentialsGrantHandler{
		signer:   signer,
		secLogFn: secLogFn,
	}
}

func (h *clientCredentialsGrantHandler) GrantType() string {
	return "client_credentials"
}

func (h *clientCredentialsGrantHandler) Handle(ctx context.Context, req domain.TokenRequest, app domain.Application, issuerURL string) (*domain.OidcTokenResult, error) {
	// 1. 强安全校验：必须验证客户端密钥凭证
	if !app.VerifySecret(req.ClientSecret) {
		if h.secLogFn != nil {
			h.secLogFn(ctx, app, "client_credentials", "应用客户端密钥验证失败")
		}
		return nil, errs.ErrApplicationSecretWrong
	}

	// 2. 确定该 M2M 机器会话请求的有效 Scopes
	var requestedScopes []string
	if req.Scope != "" {
		requestedScopes = strings.Fields(req.Scope)
	}
	allowedScopes := app.FilterAllowedScopes(requestedScopes)
	scopeStr := strings.Join(allowedScopes, " ")

	// 3. 构造 M2M 机器身份 Access Token Claims (RFC 6749 4.4.3: 主体 sub 为 ClientID)
	now := time.Now()
	ttl := 2 * time.Hour
	claims := domain.IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    strings.TrimRight(issuerURL, "/"),
			Subject:   app.ClientID, // M2M 模式下主体即为客户端应用自身标识
			Audience:  jwt.ClaimStrings{app.ClientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		PreferredUsername: app.Name,
		TenantID:          app.TenantID,
	}

	accessToken, err := h.signer.SignJWT(claims)
	if err != nil {
		return nil, fmt.Errorf("签发 M2M 机器 Access Token 失败: %w", err)
	}

	// 4. 返回标准令牌实体 (RFC 6749 4.4.3 铁律：Client Credentials 模式严禁下发 refresh_token 与 id_token)
	return &domain.OidcTokenResult{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(ttl.Seconds()),
		Scope:       scopeStr,
	}, nil
}
