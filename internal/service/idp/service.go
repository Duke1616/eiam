package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	auditevt "github.com/Duke1616/eiam/internal/event/audit"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/service/idp/grant"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/go-jose/go-jose/v4"
)

// AuthorizeRequest 授权码发起请求参数
type AuthorizeRequest struct {
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	ResponseType        string   `json:"response_type"`
	Scopes              []string `json:"scopes"`
	State               string   `json:"state"`
	Nonce               string   `json:"nonce"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	UserID              int64    `json:"user_id"`
	Username            string   `json:"username"`
	TenantID            int64    `json:"tenant_id"`
}

// AuthorizeResult 授权判定结果 (包含是否需要 Consent 页面交互)
type AuthorizeResult struct {
	RequireConsent bool   `json:"require_consent"`
	ConsentID      string `json:"consent_id,omitempty"`
	RedirectURL    string `json:"redirect_url"`
}

// IService OpenID Connect / OAuth2.0 身份提供商核心协议服务接口
//
//go:generate mockgen -source=./service.go -package=idpmocks -destination=./mocks/service.mock.go -typed IService
type IService interface {
	// Authorize 校验授权请求，对于第三方应用触发 Consent，对于第一方应用直接签发 Code
	Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResult, error)
	// GetConsentInfo 获取待确认的授权信息详情 (用于前端展示授权页面)
	GetConsentInfo(ctx context.Context, consentID string) (*domain.ConsentInfo, error)
	// ConfirmConsent 用户提交授权确认 (同意或拒绝)
	ConfirmConsent(ctx context.Context, consentID string, approved bool) (string, error)
	// ExchangeToken 使用 Grant 策略模式分发换发 Token 请求 (支持 code / refresh_token)
	ExchangeToken(ctx context.Context, req domain.TokenRequest, issuerURL string) (*domain.OidcTokenResult, error)
	// RevokeToken 吊销指定的 AccessToken 或 RefreshToken (RFC 7009)
	RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error
	// GetUserInfo 根据 Access Token 解析并返回对应的用户信息
	GetUserInfo(ctx context.Context, tokenString string) (*domain.OidcUserInfo, error)
	// GetDiscoveryConfig 获取 OpenID Connect 自动发现元数据
	GetDiscoveryConfig(ctx context.Context, issuerURL string) domain.OidcDiscovery
	// GetJWKS 获取用于客户端验签的 JSON Web Key Set 公钥集
	GetJWKS(ctx context.Context) jose.JSONWebKeySet
}

type service struct {
	repo          repository.IOAuthClientRepository
	userRepo      repository.IUserRepository
	permSvc       permission.IPermissionService
	tenantSvc     tenant.ITenantService
	cache         cache.IOidcCache
	km            IKeyManager
	auditProducer auditevt.IAuditProducer
	grantHandlers map[string]grant.IGrantHandler
}

// NewService 构造 IdP 协议服务实例
func NewService(
	repo repository.IOAuthClientRepository,
	userRepo repository.IUserRepository,
	permSvc permission.IPermissionService,
	tenantSvc tenant.ITenantService,
	cache cache.IOidcCache,
	km IKeyManager,
	auditProducer auditevt.IAuditProducer,
) IService {
	s := &service{
		repo:          repo,
		userRepo:      userRepo,
		permSvc:       permSvc,
		tenantSvc:     tenantSvc,
		cache:         cache,
		km:            km,
		auditProducer: auditProducer,
	}

	secLogFn := func(ctx context.Context, client domain.OAuthClient, action, failReason string) {
		s.recordAudit(ctx, client.TenantID, action, client.ClientID, client.Name, domain.OpStatusFailed, failReason)
	}

	// 注册授权模式策略 (Strategy Pattern)
	s.grantHandlers = map[string]grant.IGrantHandler{
		"authorization_code": grant.NewAuthCodeGrantHandler(userRepo, permSvc, cache, km, secLogFn),
		"refresh_token":      grant.NewRefreshTokenGrantHandler(userRepo, permSvc, cache, km),
	}

	return s
}

// Authorize 核心授权决策
func (s *service) Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResult, error) {
	client, err := s.repo.FindByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errs.ErrOAuthClientNotFound
	}

	if !client.HasRedirectURI(req.RedirectURI) {
		return nil, errs.ErrInvalidRedirectURI
	}

	// 1. 多租户准入校验：用户必须属于该应用所在的租户空间
	if err := s.checkTenantAccess(ctx, client.TenantID, req.UserID); err != nil {
		return nil, err
	}
	req.TenantID = client.TenantID

	// 2. 过滤有效 Scopes (使用 Domain 充血方法)
	validScopes := client.FilterAllowedScopes(req.Scopes)

	// 3. 第三方应用走 Consent 用户显式授权确认流程
	if !client.AutoConsent {
		return s.initiateConsentFlow(ctx, client, req, validScopes)
	}

	// 4. 第一方免确认应用直接签发 AuthCode 并回跳
	redirectURL, err := s.generateAndSaveAuthCode(ctx, req, validScopes)
	if err != nil {
		return nil, err
	}

	return &AuthorizeResult{
		RequireConsent: false,
		RedirectURL:    redirectURL,
	}, nil
}

// checkTenantAccess 校验用户是否具备该应用所在租户空间的成员访问权限
func (s *service) checkTenantAccess(ctx context.Context, tenantID, userID int64) error {
	targetCtx := ctxutil.WithTenantID(ctx, tenantID)
	hasAccess, err := s.tenantSvc.CheckUserTenantAccess(targetCtx, userID)
	if err != nil || !hasAccess {
		return errs.ErrTenantAccessDenied
	}
	return nil
}

// initiateConsentFlow 暂存授权确认上下文并构造 Consent 重定向结果
func (s *service) initiateConsentFlow(
	ctx context.Context,
	client domain.OAuthClient,
	req AuthorizeRequest,
	scopes []string,
) (*AuthorizeResult, error) {
	consentID, err := generateRandomString(24)
	if err != nil {
		return nil, fmt.Errorf("生成授权会话失败: %w", err)
	}

	consentInfo := domain.ConsentInfo{
		ConsentID:           consentID,
		ClientID:            client.ClientID,
		ClientName:          client.Name,
		ClientLogo:          client.Logo,
		UserID:              req.UserID,
		Username:            req.Username,
		TenantID:            req.TenantID,
		RedirectURI:         req.RedirectURI,
		Scopes:              scopes,
		ScopeDescriptions:   domain.ResolveScopeDescriptions(scopes),
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		CreatedAt:           time.Now().Unix(),
	}

	data, err := json.Marshal(consentInfo)
	if err != nil {
		return nil, fmt.Errorf("序列化授权信息失败: %w", err)
	}

	if err = s.cache.SaveConsentContext(ctx, consentID, data); err != nil {
		return nil, fmt.Errorf("暂存授权上下文失败: %w", err)
	}

	return &AuthorizeResult{
		RequireConsent: true,
		ConsentID:      consentID,
		RedirectURL:    fmt.Sprintf("/oauth/v2/consent?consent_id=%s", consentID),
	}, nil
}

// GetConsentInfo 查询待用户确认的授权详情
func (s *service) GetConsentInfo(ctx context.Context, consentID string) (*domain.ConsentInfo, error) {
	data, err := s.cache.GetConsentContext(ctx, consentID)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("授权确认会话已失效或不存在")
	}

	var info domain.ConsentInfo
	if err = json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("解析授权会话失败: %w", err)
	}
	return &info, nil
}

// ConfirmConsent 用户点击确认或拒绝
func (s *service) ConfirmConsent(ctx context.Context, consentID string, approved bool) (string, error) {
	data, err := s.cache.GetAndDelConsentContext(ctx, consentID)
	if err != nil || len(data) == 0 {
		return "", fmt.Errorf("授权确认会话已失效")
	}

	var info domain.ConsentInfo
	if err = json.Unmarshal(data, &info); err != nil {
		return "", fmt.Errorf("解析授权会话失败: %w", err)
	}

	// 用户拒绝授权：302 回跳带 error=access_denied
	if !approved {
		s.recordAudit(ctx, info.TenantID, "consent_denied", info.ClientID, info.ClientName, domain.OpStatusFailed, "用户拒绝授权")
		return buildErrorRedirectURL(info.RedirectURI, "access_denied", "用户拒绝了本次访问授权", info.State)
	}

	req := AuthorizeRequest{
		ClientID:            info.ClientID,
		RedirectURI:         info.RedirectURI,
		ResponseType:        "code",
		Scopes:              info.Scopes,
		State:               info.State,
		Nonce:               info.Nonce,
		CodeChallenge:       info.CodeChallenge,
		CodeChallengeMethod: info.CodeChallengeMethod,
		UserID:              info.UserID,
		Username:            info.Username,
		TenantID:            info.TenantID,
	}

	s.recordAudit(ctx, info.TenantID, "consent_granted", info.ClientID, info.ClientName, domain.OpStatusSuccess, "")
	return s.generateAndSaveAuthCode(ctx, req, info.Scopes)
}

// ExchangeToken 使用策略模式分发处理各种 GrantType
func (s *service) ExchangeToken(ctx context.Context, req domain.TokenRequest, issuerURL string) (*domain.OidcTokenResult, error) {
	if req.GrantType == "" {
		req.GrantType = "authorization_code"
	}

	handler, ok := s.grantHandlers[req.GrantType]
	if !ok {
		return nil, fmt.Errorf("unsupported_grant_type: 不支持的授权模式 %s", req.GrantType)
	}

	client, err := s.repo.FindByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, errs.ErrOAuthClientNotFound
	}

	if !client.IsGrantTypeAllowed(req.GrantType) {
		return nil, fmt.Errorf("unauthorized_client: 应用未开通 %s 授权模式", req.GrantType)
	}

	result, err := handler.Handle(ctx, req, client, issuerURL)
	if err != nil {
		s.recordAudit(ctx, client.TenantID, "exchange_token", client.ClientID, client.Name, domain.OpStatusFailed, err.Error())
		return nil, err
	}

	s.recordAudit(ctx, client.TenantID, "exchange_token", client.ClientID, client.Name, domain.OpStatusSuccess, "")
	return result, nil
}

// RevokeToken 吊销 Token (RFC 7009)
func (s *service) RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
	if token == "" {
		return nil // RFC 7009 规定 token 为空也应返回 200 OK
	}

	client, err := s.repo.FindByClientID(ctx, clientID)
	if err != nil {
		return errs.ErrOAuthClientNotFound
	}

	if !client.VerifySecret(clientSecret) {
		return errs.ErrOAuthClientSecretWrong
	}

	// 1. 若为 RefreshToken，直接从 Redis 会话中移除
	_ = s.cache.DeleteRefreshToken(ctx, token)

	// 2. 将 Token 加入黑名单缓存 (24 小时过期)
	_ = s.cache.RevokeToken(ctx, token, 24*time.Hour)

	s.recordAudit(ctx, client.TenantID, "revoke_token", client.ClientID, client.Name, domain.OpStatusSuccess, "")
	return nil
}

// GetUserInfo 解析令牌并返回标准用户信息
func (s *service) GetUserInfo(ctx context.Context, tokenString string) (*domain.OidcUserInfo, error) {
	// 校验是否已被吊销
	revoked, err := s.cache.IsTokenRevoked(ctx, tokenString)
	if err == nil && revoked {
		return nil, fmt.Errorf("token 已被撤销")
	}

	var claims domain.IDTokenClaims
	_, err = s.km.VerifyJWT(tokenString, &claims)
	if err != nil {
		return nil, fmt.Errorf("令牌无效或已过期: %w", err)
	}

	userID, _ := strconv.ParseInt(claims.Subject, 10, 64)

	// 绑定 Token 所在租户空间，获取该租户下的最新角色与名片信息
	roles, profile := grant.FetchUserClaims(ctx, claims.TenantID, userID, claims.PreferredUsername, s.permSvc, s.userRepo)

	return &domain.OidcUserInfo{
		Subject:           strconv.FormatInt(userID, 10),
		PreferredUsername: claims.PreferredUsername,
		Name:              profile.Nickname,
		Nickname:          profile.Nickname,
		Email:             profile.Email,
		EmailVerified:     profile.Email != "",
		PhoneNumber:       profile.Phone,
		TenantID:          claims.TenantID,
		Roles:             roles,
	}, nil
}

// GetDiscoveryConfig 返回标准 OIDC 发现元数据
func (s *service) GetDiscoveryConfig(ctx context.Context, issuerURL string) domain.OidcDiscovery {
	return domain.NewOidcDiscovery(issuerURL)
}

// GetJWKS 获取公钥集合
func (s *service) GetJWKS(ctx context.Context) jose.JSONWebKeySet {
	return s.km.PublicKeySet()
}

// generateAndSaveAuthCode 生成 32 字节随机 AuthCode 并存入 Redis
func (s *service) generateAndSaveAuthCode(ctx context.Context, req AuthorizeRequest, scopes []string) (string, error) {
	code, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("生成授权码失败: %w", err)
	}

	authCode := domain.AuthCode{
		Code:                code,
		ClientID:            req.ClientID,
		UserID:              req.UserID,
		Username:            req.Username,
		TenantID:            req.TenantID,
		RedirectURI:         req.RedirectURI,
		Scopes:              scopes,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		CreatedAt:           time.Now(),
	}

	data, err := json.Marshal(authCode)
	if err != nil {
		return "", fmt.Errorf("序列化授权码上下文失败: %w", err)
	}

	if err = s.cache.SaveAuthCodeContext(ctx, code, data); err != nil {
		return "", fmt.Errorf("缓存授权码失败: %w", err)
	}

	return authCode.BuildRedirectURL(req.State)
}

func (s *service) recordAudit(ctx context.Context, tenantID int64, action, resourceID, resourceName, status, failReason string) {
	if s.auditProducer == nil {
		return
	}
	go func() {
		defer func() { _ = recover() }()
		asyncCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		_ = s.auditProducer.RecordOperation(asyncCtx, domain.OperationLog{
			TenantID:     tenantID,
			Service:      "iam",
			Module:       "idp",
			Action:       action,
			ResourceID:   resourceID,
			ResourceName: resourceName,
			Status:       status,
			FailReason:   failReason,
			ClientIP:     ctxutil.GetClientIP(ctx),
			UserAgent:    ctxutil.GetUserAgent(ctx),
			Ctime:        time.Now().UnixMilli(),
		})
	}()
}

func buildErrorRedirectURL(redirectURI, errCode, errDesc, state string) (string, error) {
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	res := fmt.Sprintf("%s%serror=%s&error_description=%s", redirectURI, sep, errCode, errDesc)
	if state != "" {
		res += "&state=" + state
	}
	return res, nil
}
