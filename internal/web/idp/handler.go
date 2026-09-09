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
	cassvc "github.com/Duke1616/eiam/internal/service/idp/cas"
	oidcsvc "github.com/Duke1616/eiam/internal/service/idp/oidc"
	samlsvc "github.com/Duke1616/eiam/internal/service/idp/saml"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/sessionx"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"github.com/samber/lo"
	"github.com/spf13/viper"
)

// Handler 统一身份提供商 Web 接入层 (原生 OIDC, CAS 2.0/3.0 与 SAML 2.0 实现)
type Handler struct {
	capability.IRegistry
	appSvc  idpsvc.IService
	svc     oidcsvc.IOidcService
	casSvc  cassvc.ICasService
	samlSvc samlsvc.ISamlService
	logger  *elog.Component
}

// NewHandler 构造 IdP Web 处理器
func NewHandler(appSvc idpsvc.IService, svc oidcsvc.IOidcService, casSvc cassvc.ICasService, samlSvc samlsvc.ISamlService) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "idp", "统一身份提供商").DefaultScope(capability.ScopeTenant),
		appSvc:    appSvc,
		svc:       svc,
		casSvc:    casSvc,
		samlSvc:   samlSvc,
		logger:    elog.DefaultLogger,
	}
}

// PublicRoutes 注册公开的标准身份协议端点 (OIDC, CAS, SAML 与 Consent 交互)
func (h *Handler) PublicRoutes(server *gin.Engine) {
	// 透明兼容微服务网关/前端反向代理（如通过 /api/iam 统一转发并 rewrite 为 /api 的场景）。
	// 架构权衡：避免在 Gin 中将所有协议路由重复注册两遍（保持 Radix 路由树的单份与纯粹），
	// 仅在请求命中标准身份协议前缀时内部透明剥离 /api 前缀，直接流转至根路由。
	server.Use(func(c *gin.Context) {
		p := c.Request.URL.Path
		if strings.HasPrefix(p, "/api/.well-known") ||
			strings.HasPrefix(p, "/api/oauth") ||
			strings.HasPrefix(p, "/api/cas") ||
			strings.HasPrefix(p, "/api/saml") {
			c.Request.URL.Path = strings.TrimPrefix(p, "/api")
		}
		c.Next()
	})

	// 1. 标准协议端点 (遵循 RFC / 官方协议标准注册在根路径，仅维护单份路由树)
	h.registerProtocolRoutes(&server.RouterGroup)

	// 2. 用户授权确认交互端点 (Consent Flow，供前端应用管理交互调用)
	server.GET("/api/idp/consent", h.GetConsent)
	server.POST("/api/idp/consent", h.ConfirmConsent)
}

func (h *Handler) registerProtocolRoutes(rg *gin.RouterGroup) {
	// 1. 标准 OpenID Connect 自动发现与 JWKS 端点
	rg.GET("/.well-known/openid-configuration", h.Discovery)
	rg.GET("/oauth/v2/jwks", h.JWKS)

	// 2. 授权入口 (支持 GET 浏览器跳转与 POST 表单)
	rg.GET("/oauth/v2/authorize", h.Authorize)
	rg.POST("/oauth/v2/authorize", h.Authorize)

	// 3. 授权码换发 Token 端点 (支持 code 与 refresh_token 策略)
	rg.POST("/oauth/v2/token", h.Token)
	rg.POST("/oauth/token", h.Token) // 别名兼容

	// 4. 令牌撤销端点 (RFC 7009 Token Revocation)
	rg.POST("/oauth/v2/revoke", h.Revoke)

	// 5. 用户信息查询端点
	rg.GET("/userinfo", h.UserInfo)
	rg.POST("/userinfo", h.UserInfo)

	// 6. 单点登出端点 (OIDC RP-Initiated Logout)
	rg.GET("/oauth/v2/logout", h.Logout)
	rg.POST("/oauth/v2/logout", h.Logout)

	// 7. 标准 CAS 2.0 / 3.0 单点登录协议端点
	rg.GET("/cas/login", h.CasLogin)
	rg.GET("/cas/serviceValidate", h.CasServiceValidate)
	rg.GET("/cas/p3/serviceValidate", h.CasServiceValidate) // CAS 3.0 别名
	rg.GET("/cas/validate", h.CasValidate)                  // CAS 1.0 兼容
	rg.GET("/cas/logout", h.CasLogout)

	// 8. 标准 SAML 2.0 单点登录协议端点
	rg.GET("/saml/metadata", h.SamlMetadata)
	rg.GET("/saml/certificate", h.SamlCertificate)
	rg.GET("/saml/sso", h.SamlSSO)
	rg.POST("/saml/sso", h.SamlSSO)
	rg.GET("/saml/login/:id", h.SamlIdPInitiatedLogin)
}

// PrivateRoutes 注册租户管理员的应用管理接口 (需要登录态与鉴权保护)
func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/idp/application")
	g.POST("/create", h.Define("创建接入应用", "create").
		Bind(ginx.BS[CreateApplicationReq](h.CreateApplication)),
	)
	g.POST("/update", h.Define("更新接入应用", "update").
		Bind(ginx.B[UpdateApplicationReq](h.UpdateApplication)),
	)
	g.POST("/reset_secret/:id", h.Define("重置应用密钥", "reset_secret").
		Bind(ginx.W(h.ResetApplicationSecret)),
	)
	g.POST("/list", h.Define("接入应用列表", "list").
		Bind(ginx.BS[ListApplicationReq](h.ListApplications)),
	)
	g.DELETE("/delete/:id", h.Define("删除接入应用", "delete").
		Bind(ginx.W(h.DeleteApplication)),
	)
	g.GET("/detail/:id", h.Define("接入应用详情", "detail").
		Bind(ginx.W(h.GetApplicationDetail)),
	)

	samlGroup := server.Group("/api/idp/saml")
	samlGroup.GET("/descriptor", h.Define("获取SAML接入描述符", "saml_descriptor").
		Bind(ginx.W(h.SamlDescriptor)),
	)
	samlGroup.POST("/certificate/rotate", h.Define("轮换SAML证书", "saml_rotate_cert").
		Bind(ginx.B[RotateCertificateReq](h.SamlRotateCertificate)),
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

	// 1. 检查主站登录态并拦截未登录重定向
	userSess, ok := h.requireAuth(c)
	if !ok {
		return
	}

	// 2. 用户已登录，调用 Service 计算授权或 Consent 交互
	result, err := h.svc.Authorize(c.Request.Context(), oidcsvc.AuthorizeRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scopes:              strings.Fields(scope),
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		UserID:              userSess.UserID,
		Username:            userSess.Username,
		TenantID:            userSess.TenantID,
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

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "OK",
		"data": info,
	})
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

	_ = sessionx.DestroyGin(c)

	if postLogoutRedirectURI != "" {
		target := appendQueryParam(postLogoutRedirectURI, "state", state)
		c.Redirect(http.StatusFound, target)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "已成功注销登录态"})
}

func appendQueryParam(rawURL, key, val string) string {
	if val == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	q.Set(key, val)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func (h *Handler) resolveIssuerURL(c *gin.Context) string {
	cfgIssuer := viper.GetString("idp.oidc.issuer_url")
	if cfgIssuer == "" {
		cfgIssuer = viper.GetString("idp.issuer_url")
	}
	if cfgIssuer != "" {
		return cfgIssuer
	}
	scheme := lo.Ternary(c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https", "https", "http")
	return fmt.Sprintf("%s://%s", scheme, c.Request.Host)
}

// --- 接入应用管理接口 ---

// CreateApplication 创建接入应用
func (h *Handler) CreateApplication(ctx *ginx.Context, req CreateApplicationReq, sess session.Session) (ginx.Result, error) {
	tid, _ := sess.Get(ctx.Request.Context(), "tenant_id").AsInt64()
	if tid <= 0 {
		tid = int64(ctxutil.GetTenantID(ctx.Request.Context()))
	}

	protocol := domain.Protocol(lo.CoalesceOrEmpty(req.Protocol, string(domain.ProtocolOIDC)))

	app := domain.Application{
		TenantID:      tid,
		Protocol:      protocol,
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

	created, err := h.appSvc.Create(ctx.Request.Context(), app)
	if err != nil {
		return ErrIdpClientCreateFailed, err
	}

	return ginx.Result{Data: h.toVO(created)}, nil
}

// UpdateApplication 更新接入应用
func (h *Handler) UpdateApplication(ctx *ginx.Context, req UpdateApplicationReq) (ginx.Result, error) {
	if err := h.appSvc.Update(ctx.Request.Context(), req.ToDomain()); err != nil {
		return ErrIdpClientUpdateFailed, err
	}

	return ginx.Result{Msg: "更新应用成功"}, nil
}

// ResetApplicationSecret 重置应用客户端密钥
func (h *Handler) ResetApplicationSecret(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrIdpClientInvalidID, err
	}

	newSecret, err := h.appSvc.ResetSecret(ctx.Request.Context(), id)
	if err != nil {
		return ErrIdpClientResetFailed, err
	}

	return ginx.Result{
		Data: ResetSecretResp{ClientSecret: newSecret},
		Msg:  "重置密钥成功，请妥善保管明文密钥，后续将无法再次查看",
	}, nil
}

// ListApplications 分页查询应用列表 (上下文携带租户，依托 gormx 自动隔离与全局共享)
func (h *Handler) ListApplications(ctx *ginx.Context, req ListApplicationReq, sess session.Session) (ginx.Result, error) {
	if req.Limit <= 0 {
		req.Limit = 10
	}

	apps, total, err := h.appSvc.List(ctx.Request.Context(), req.Offset, req.Limit)
	if err != nil {
		return ErrIdpClientListFailed, err
	}

	voList := lo.Map(apps, func(a domain.Application, _ int) ApplicationVO {
		return h.toVO(a)
	})

	return ginx.Result{
		Data: map[string]any{
			"total":        total,
			"applications": voList,
			"clients":      voList, // 兼容前端旧字段
		},
	}, nil
}

// DeleteApplication 删除应用
func (h *Handler) DeleteApplication(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrIdpClientInvalidID, err
	}

	if err = h.appSvc.Delete(ctx.Request.Context(), id); err != nil {
		return ErrIdpClientDeleteFailed, err
	}

	return ginx.Result{Msg: "删除应用成功"}, nil
}

// GetApplicationDetail 查询应用详情
func (h *Handler) GetApplicationDetail(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrIdpClientInvalidID, err
	}

	app, err := h.appSvc.GetByID(ctx.Request.Context(), id)
	if err != nil {
		return ErrIdpClientInvalidID, err
	}

	return ginx.Result{Data: h.toVO(app)}, nil
}

func (h *Handler) toVO(app domain.Application) ApplicationVO {
	return ApplicationVO{
		ID:            app.ID,
		TenantID:      app.TenantID,
		Protocol:      lo.CoalesceOrEmpty(string(app.Protocol), string(domain.ProtocolOIDC)),
		ClientID:      app.ClientID,
		ClientSecret:  app.ClientSecret,
		Name:          app.Name,
		Logo:          app.Logo,
		RedirectURIs:  app.RedirectURIs,
		ResponseTypes: app.ResponseTypes,
		GrantTypes:    app.GrantTypes,
		Scopes:        app.Scopes,
		IsPublic:      app.IsPublic,
		AutoConsent:   app.AutoConsent,
		Ctime:         app.Ctime,
		Utime:         app.Utime,
	}
}
