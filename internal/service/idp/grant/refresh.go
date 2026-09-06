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
	"github.com/samber/lo"
)

type refreshTokenGrantHandler struct {
	userRepo repository.IUserRepository
	permSvc  permission.IPermissionService
	cache    cache.IOidcCache
	signer   IKeySigner
}

// NewRefreshTokenGrantHandler 构造 RefreshToken 续期策略实例
func NewRefreshTokenGrantHandler(
	userRepo repository.IUserRepository,
	permSvc permission.IPermissionService,
	cache cache.IOidcCache,
	signer IKeySigner,
) IGrantHandler {
	return &refreshTokenGrantHandler{
		userRepo: userRepo,
		permSvc:  permSvc,
		cache:    cache,
		signer:   signer,
	}
}

func (h *refreshTokenGrantHandler) GrantType() string {
	return "refresh_token"
}

func (h *refreshTokenGrantHandler) Handle(ctx context.Context, req domain.TokenRequest, client domain.OAuthClient, issuerURL string) (*domain.OidcTokenResult, error) {
	if req.RefreshToken == "" {
		return nil, fmt.Errorf("缺少 refresh_token 参数")
	}

	// 1. 校验客户端凭证
	if !client.VerifySecret(req.ClientSecret) {
		return nil, errs.ErrOAuthClientSecretWrong
	}

	// 2. 从缓存读取 RefreshToken 会话
	data, err := h.cache.GetRefreshToken(ctx, req.RefreshToken)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("refresh_token 无效或已过期")
	}

	var session domain.RefreshTokenSession
	if err = json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("反序列化 refresh_token 会话失败: %w", err)
	}

	if session.ClientID != client.ClientID {
		return nil, fmt.Errorf("refresh_token 归属客户端不匹配")
	}

	// 3. 执行 Token 轮转 (Token Rotation): 销毁旧 RefreshToken 并写入新 RefreshToken
	_ = h.cache.DeleteRefreshToken(ctx, req.RefreshToken)

	newRefreshToken, err := GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("生成新 refresh_token 失败: %w", err)
	}

	session.RefreshToken = newRefreshToken
	session.CreatedAt = time.Now().Unix()
	sessBytes, _ := json.Marshal(session)
	_ = h.cache.SaveRefreshToken(ctx, newRefreshToken, sessBytes)
	_ = h.cache.TrackUserRefreshToken(ctx, strconv.FormatInt(session.UserID, 10), newRefreshToken)

	// 4. 重新获取用户最新角色与名片
	roles, _ := h.permSvc.GetRolesForUser(ctx, session.Username)

	var profile UserProfile
	user, err := h.userRepo.FindById(ctx, session.UserID)
	if err == nil {
		profile = UserProfile{
			Nickname: user.Profile.Nickname,
			Email:    user.Email,
			Phone:    user.Profile.Phone,
		}
	}

	// 5. 统一签发新 AccessToken 与 IDToken
	accessToken, idToken, err := IssueTokenPair(h.signer, TokenPayload{
		IssuerURL: issuerURL,
		ClientID:  client.ClientID,
		UserID:    session.UserID,
		Username:  session.Username,
		TenantID:  session.TenantID,
		Profile:   profile,
		Roles:     roles,
	})
	if err != nil {
		return nil, err
	}

	return &domain.OidcTokenResult{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    7200,
		IDToken:      idToken,
		RefreshToken: newRefreshToken,
		Scope:        strings.Join(lo.Intersect(session.Scopes, client.Scopes), " "),
	}, nil
}
