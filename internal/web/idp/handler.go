package idp

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	idpsvc "github.com/Duke1616/eiam/internal/service/idp"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
	"github.com/spf13/viper"
)

// Handler 统一身份提供商 Web 接入层 (企业级原生 OIDC 实现)
type Handler struct {
	capability.IRegistry
	clientSvc idpsvc.IOAuthClientService
	svc       idpsvc.IService
}

// NewHandler 构造 IdP Web 处理器
func NewHandler(clientSvc idpsvc.IOAuthClientService, svc idpsvc.IService) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "idp", "统一身份提供商").DefaultScope(capability.ScopeTenant),
		clientSvc: clientSvc,
		svc:       svc,
	}
}

// PublicRoutes 注册公开的标准 OIDC 协议端点
func (h *Handler) PublicRoutes(server *gin.Engine) {
	// 1. 标准 OpenID Connect 自动发现与 JWKS 端点
	server.GET("/.well-known/openid-configuration", h.Discovery)
	server.GET("/oauth/v2/jwks", h.JWKS)

	// 2. 授权入口 (支持 GET 浏览器跳转与 POST 表单)
	server.GET("/oauth/v2/authorize", h.Authorize)
	server.POST("/oauth/v2/authorize", h.Authorize)

	// 3. 用户授权确认交互端点 (Consent Flow)
	server.GET("/oauth/v2/consent", h.GetConsent)
	server.POST("/oauth/v2/consent", h.ConfirmConsent)

	// 4. 授权码换发 Token 端点 (支持 code 与 refresh_token 策略)
	server.POST("/oauth/v2/token", h.Token)
	server.POST("/oauth/token", h.Token) // 别名兼容

	// 5. 令牌撤销端点 (RFC 7009 Token Revocation)
	server.POST("/oauth/v2/revoke", h.Revoke)

	// 6. 用户信息查询端点
	server.GET("/userinfo", h.UserInfo)
	server.POST("/userinfo", h.UserInfo)

	// 7. 单点登出端点 (OIDC RP-Initiated Logout)
	server.GET("/oauth/v2/logout", h.Logout)
	server.POST("/oauth/v2/logout", h.Logout)
}

// PrivateRoutes 注册租户管理员的应用管理接口 (OPA/RBAC 鉴权保护)
func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/idp/client")

	g.POST("/create", h.Define("创建接入应用", "create").
		Bind(ginx.BS[CreateOAuthClientReq](h.CreateClient)),
	)
	g.POST("/update", h.Define("更新接入应用", "update").
		Bind(ginx.B[UpdateOAuthClientReq](h.UpdateClient)),
	)
	g.POST("/reset_secret/:id", h.Define("重置应用密钥", "reset_secret").
		Bind(ginx.W(h.ResetClientSecret)),
	)
	g.POST("/list", h.Define("接入应用列表", "list").
		Bind(ginx.BS[ListOAuthClientReq](h.ListClients)),
	)
	g.DELETE("/delete/:id", h.Define("删除接入应用", "delete").
		Bind(ginx.W(h.DeleteClient)),
	)
	g.GET("/detail/:id", h.Define("接入应用详情", "detail").
		Bind(ginx.W(h.GetClientDetail)),
	)
}

// --- OIDC 标准协议端点实现 ---

// Discovery 输出 OpenID Connect Discovery 元数据
func (h *Handler) Discovery(c *gin.Context) {
	issuerURL := h.resolveIssuerURL(c)
	c.JSON(http.StatusOK, h.svc.GetDiscoveryConfig(c.Request.Context(), issuerURL))
}

// JWKS 输出 RSA 公钥集合 (JSON Web Key Set)
func (h *Handler) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, h.svc.GetJWKS(c.Request.Context()))
}

// Authorize 核心授权端点 (RFC 6749 Section 4.1.1)
func (h *Handler) Authorize(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.DefaultQuery("response_type", "code")
	scope := c.DefaultQuery("scope", "openid")
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.DefaultQuery("code_challenge_method", "S256")

	if clientID == "" || redirectURI == "" {
		c.String(http.StatusBadRequest, "缺少 client_id 或 redirect_uri 参数")
		return
	}

	// 1. 检查主站登录态
	sess, err := session.Get(&ginx.Context{Context: c})
	claims := session.Claims{}
	if err == nil && sess != nil {
		claims = sess.Claims()
	}

	// 2. 若未登录，重定向到登录页并暂存当前请求完整 URL
	if claims.Uid <= 0 {
		loginURL := viper.GetString("idp.login_url")
		if loginURL == "" {
			loginURL = "/login"
		}
		rawReqURL := c.Request.URL.RequestURI()
		c.Redirect(http.StatusFound, fmt.Sprintf("%s?redirect=%s", loginURL, url.QueryEscape(rawReqURL)))
		return
	}

	// 3. 用户已登录，调用 Service 计算授权或 Consent 交互
	username, _ := sess.Get(c.Request.Context(), "username").AsString()
	tid, _ := sess.Get(c.Request.Context(), "tenant_id").AsInt64()

	result, err := h.svc.Authorize(c.Request.Context(), idpsvc.AuthorizeRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scopes:              strings.Fields(scope),
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		UserID:              claims.Uid,
		Username:            username,
		TenantID:            tid,
	})
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("授权失败: %v", err))
		return
	}

	c.Redirect(http.StatusFound, result.RedirectURL)
}

// GetConsent 获取待确认授权的应用信息与申请的权限清单
func (h *Handler) GetConsent(c *gin.Context) {
	consentID := c.Query("consent_id")
	if consentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 consent_id 参数"})
		return
	}

	info, err := h.svc.GetConsentInfo(c.Request.Context(), consentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, info)
}

// ConfirmConsent 用户提交授权决策 (同意或拒绝)
func (h *Handler) ConfirmConsent(c *gin.Context) {
	consentID := c.PostForm("consent_id")
	approvedStr := c.DefaultPostForm("approved", "false")
	approved, _ := strconv.ParseBool(approvedStr)

	if consentID == "" {
		c.String(http.StatusBadRequest, "缺少 consent_id 参数")
		return
	}

	targetURL, err := h.svc.ConfirmConsent(c.Request.Context(), consentID, approved)
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("提交授权决策失败: %v", err))
		return
	}

	c.Redirect(http.StatusFound, targetURL)
}

// Token 授权码换 Token 端点 (支持 authorization_code 与 refresh_token 策略模式)
func (h *Handler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")
	refreshToken := c.PostForm("refresh_token")
	clientID, clientSecret := h.extractClientCredentials(c)

	issuerURL := h.resolveIssuerURL(c)
	resp, err := h.svc.ExchangeToken(c.Request.Context(), domain.TokenRequest{
		GrantType:    grantType,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURI:  redirectURI,
		RefreshToken: refreshToken,
	}, issuerURL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, resp)
}

// Revoke 令牌撤销端点 (RFC 7009)
func (h *Handler) Revoke(c *gin.Context) {
	token := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint")
	clientID, clientSecret := h.extractClientCredentials(c)

	if err := h.svc.RevokeToken(c.Request.Context(), token, tokenTypeHint, clientID, clientSecret); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client", "error_description": err.Error()})
		return
	}

	c.Status(http.StatusOK)
}

// extractClientCredentials 统一从 POST 表单或 HTTP Basic Auth 头部中提取客户端凭证
func (h *Handler) extractClientCredentials(c *gin.Context) (clientID, clientSecret string) {
	clientID = c.PostForm("client_id")
	clientSecret = c.PostForm("client_secret")

	// 优先从 HTTP Basic Auth 头部提取 client_id 和 client_secret
	if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(strings.ToLower(authHeader), "basic ") {
		payload, err := base64.StdEncoding.DecodeString(authHeader[6:])
		if err == nil {
			parts := strings.SplitN(string(payload), ":", 2)
			if len(parts) == 2 {
				clientID, _ = url.QueryUnescape(parts[0])
				clientSecret, _ = url.QueryUnescape(parts[1])
			}
		}
	}
	return clientID, clientSecret
}

// UserInfo 用户信息端点 (RFC OpenID Connect Core Section 5.3)
func (h *Handler) UserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "缺少 Bearer Token"})
		return
	}

	tokenStr := strings.TrimSpace(authHeader[7:])
	info, err := h.svc.GetUserInfo(c.Request.Context(), tokenStr)
	if err != nil {
		c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, info)
}

// Logout 单点注销端点 (OIDC RP-Initiated Logout)
func (h *Handler) Logout(c *gin.Context) {
	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	state := c.Query("state")

	// 调用 DefaultProvider().Destroy 清理会话，联动触发 TokenCarrier.Clear 擦除浏览器 Cookie
	gctx := &ginx.Context{Context: c}
	if err := session.DefaultProvider().Destroy(gctx); err != nil {
		if sess, getErr := session.Get(gctx); getErr == nil && sess != nil {
			_ = sess.Destroy(c)
		}
	}

	if postLogoutRedirectURI != "" {
		target := postLogoutRedirectURI
		if state != "" {
			sep := "?"
			if strings.Contains(target, "?") {
				sep = "&"
			}
			target = fmt.Sprintf("%s%sstate=%s", target, sep, url.QueryEscape(state))
		}
		c.Redirect(http.StatusFound, target)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "已成功注销登录态"})
}

func (h *Handler) resolveIssuerURL(c *gin.Context) string {
	cfgIssuer := viper.GetString("idp.issuer_url")
	if cfgIssuer != "" {
		return cfgIssuer
	}
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, c.Request.Host)
}

// --- 接入应用管理接口 ---

// CreateClient 创建接入应用
func (h *Handler) CreateClient(ctx *ginx.Context, req CreateOAuthClientReq, sess session.Session) (ginx.Result, error) {
	tid, _ := sess.Get(ctx.Request.Context(), "tenant_id").AsInt64()
	if tid <= 0 {
		tid = int64(ctxutil.GetTenantID(ctx.Request.Context()))
	}

	client := domain.OAuthClient{
		TenantID:      tid,
		ClientID:      req.ClientID,
		Name:          req.Name,
		Logo:          req.Logo,
		RedirectURIs:  req.RedirectURIs,
		ResponseTypes: req.ResponseTypes,
		GrantTypes:    req.GrantTypes,
		Scopes:        req.Scopes,
		IsPublic:      req.IsPublic,
		AutoConsent:   req.AutoConsent,
	}

	created, err := h.clientSvc.CreateClient(ctx.Request.Context(), client)
	if err != nil {
		return ErrIdpClientCreateFailed, err
	}

	return ginx.Result{Data: h.toVO(created)}, nil
}

// UpdateClient 更新接入应用
func (h *Handler) UpdateClient(ctx *ginx.Context, req UpdateOAuthClientReq) (ginx.Result, error) {
	client := domain.OAuthClient{
		ID:            req.ID,
		Name:          req.Name,
		Logo:          req.Logo,
		RedirectURIs:  req.RedirectURIs,
		ResponseTypes: req.ResponseTypes,
		GrantTypes:    req.GrantTypes,
		Scopes:        req.Scopes,
		IsPublic:      req.IsPublic,
		AutoConsent:   req.AutoConsent,
	}

	if err := h.clientSvc.UpdateClient(ctx.Request.Context(), client); err != nil {
		return ErrIdpClientUpdateFailed, err
	}

	return ginx.Result{Msg: "更新应用成功"}, nil
}

// ResetClientSecret 重置应用客户端密钥
func (h *Handler) ResetClientSecret(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrIdpClientInvalidID, err
	}

	newSecret, err := h.clientSvc.ResetClientSecret(ctx.Request.Context(), id)
	if err != nil {
		return ErrIdpClientResetFailed, err
	}

	return ginx.Result{
		Data: ResetSecretResp{ClientSecret: newSecret},
		Msg:  "重置密钥成功，请妥善保管明文密钥，后续将无法再次查看",
	}, nil
}

// ListClients 租户级分页查询应用列表
func (h *Handler) ListClients(ctx *ginx.Context, req ListOAuthClientReq, sess session.Session) (ginx.Result, error) {
	tid, _ := sess.Get(ctx.Request.Context(), "tenant_id").AsInt64()
	if tid <= 0 {
		tid = int64(ctxutil.GetTenantID(ctx.Request.Context()))
	}

	if req.Limit <= 0 {
		req.Limit = 10
	}

	clients, total, err := h.clientSvc.ListClients(ctx.Request.Context(), tid, req.Offset, req.Limit)
	if err != nil {
		return ErrIdpClientListFailed, err
	}

	voList := lo.Map(clients, func(c domain.OAuthClient, _ int) OAuthClientVO {
		return h.toVO(c)
	})

	return ginx.Result{
		Data: map[string]any{
			"total":   total,
			"clients": voList,
		},
	}, nil
}

// DeleteClient 删除应用
func (h *Handler) DeleteClient(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrIdpClientInvalidID, err
	}

	if err = h.clientSvc.DeleteClient(ctx.Request.Context(), id); err != nil {
		return ErrIdpClientDeleteFailed, err
	}

	return ginx.Result{Msg: "删除应用成功"}, nil
}

// GetClientDetail 查询应用详情
func (h *Handler) GetClientDetail(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrIdpClientInvalidID, err
	}

	client, err := h.clientSvc.GetClientByID(ctx.Request.Context(), id)
	if err != nil {
		return ErrIdpClientInvalidID, err
	}

	return ginx.Result{Data: h.toVO(client)}, nil
}

func (h *Handler) toVO(client domain.OAuthClient) OAuthClientVO {
	return OAuthClientVO{
		ID:            client.ID,
		TenantID:      client.TenantID,
		ClientID:      client.ClientID,
		ClientSecret:  client.ClientSecret,
		Name:          client.Name,
		Logo:          client.Logo,
		RedirectURIs:  client.RedirectURIs,
		ResponseTypes: client.ResponseTypes,
		GrantTypes:    client.GrantTypes,
		Scopes:        client.Scopes,
		IsPublic:      client.IsPublic,
		AutoConsent:   client.AutoConsent,
		Ctime:         client.Ctime,
		Utime:         client.Utime,
	}
}
