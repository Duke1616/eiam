package identity_source

import (
	"github.com/Duke1616/eiam/internal/domain"
	idsvc "github.com/Duke1616/eiam/internal/service/identity_source"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

type Handler struct {
	capability.IRegistry
	svc idsvc.IService
}

func NewHandler(svc idsvc.IService) *Handler {
	return &Handler{
		svc:       svc,
		IRegistry: capability.NewRegistry("iam", "identity_source", "身份源管理").DefaultScope(capability.ScopeSystem),
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/identity_source")
	g.GET("/enabled_providers", ginx.W(h.EnabledProviders))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/identity_source")

	g.POST("/save", h.Capability("保存身份源", "save").
		Handle(ginx.B[SaveIdentitySourceReq](h.Save)),
	)
	g.POST("/list", h.Capability("身份源列表", "view").
		Handle(ginx.W(h.List)),
	)
	g.DELETE("/delete/:id", h.Capability("删除身份源", "delete").
		Handle(ginx.W(h.Delete)),
	)
	g.GET("/detail/:id", h.Capability("身份源详情", "detail").
		Handle(ginx.W(h.Detail)),
	)
	g.POST("/test", h.Capability("测试身份源连接", "test").
		Handle(ginx.B[SaveIdentitySourceReq](h.Test)),
	)
	g.POST("/toggle/:id", h.Capability("切换启用状态", "toggle").
		Handle(ginx.W(h.ToggleEnabled)),
	)
}

// Save 保存身份源配置
func (h *Handler) Save(ctx *ginx.Context, req SaveIdentitySourceReq) (ginx.Result, error) {
	id, err := h.svc.Save(ctx.Request.Context(), h.toDomain(req))
	if err != nil {
		return ErrIdentitySourceSaveFailed, err
	}
	return ginx.Result{Data: id}, nil
}

// List 获取身份源列表
func (h *Handler) List(ctx *ginx.Context) (ginx.Result, error) {
	sources, err := h.svc.List(ctx.Request.Context())
	if err != nil {
		return ErrIdentitySourceListFailed, err
	}

	return ginx.Result{
		Data: lo.Map(sources, func(src domain.IdentitySource, _ int) IdentitySourceVO {
			return h.toVo(src)
		}),
	}, nil
}

// Delete 删除身份源
func (h *Handler) Delete(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrIdentitySourceInvalidId, err
	}

	err = h.svc.Delete(ctx.Request.Context(), id)
	if err != nil {
		return ErrIdentitySourceDeleteFailed, err
	}
	return ginx.Result{Msg: "删除成功"}, nil
}

// Detail 获取身份源详情
func (h *Handler) Detail(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrIdentitySourceInvalidId, err
	}

	src, err := h.svc.GetByID(ctx.Request.Context(), id)
	if err != nil {
		return ErrIdentitySourceGetFailed, err
	}

	return ginx.Result{Data: h.toVo(src)}, nil
}

// Test 测试 LDAP 连通性
func (h *Handler) Test(ctx *ginx.Context, req SaveIdentitySourceReq) (ginx.Result, error) {
	err := h.svc.TestConnection(ctx.Request.Context(), h.toDomain(req))
	if err != nil {
		res := ErrIdentitySourceTestConnectionFailed
		res.Msg = res.Msg + ": " + err.Error()
		return res, err
	}
	return ginx.Result{Msg: "连接成功"}, nil
}

// ToggleEnabled 切换身份源启用状态
func (h *Handler) ToggleEnabled(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrIdentitySourceInvalidId, err
	}

	err = h.svc.ToggleEnabled(ctx.Request.Context(), id)
	if err != nil {
		return ErrIdentitySourceSaveFailed, err
	}

	return ginx.Result{Msg: "状态切换成功"}, nil
}

func (h *Handler) EnabledProviders(ctx *ginx.Context) (ginx.Result, error) {
	providers, err := h.svc.GetEnabledProviderTypes(ctx.Request.Context())
	if err != nil {
		return ErrIdentitySourceListFailed, err
	}
	return ginx.Result{Data: providers}, nil
}

func (h *Handler) toDomain(req SaveIdentitySourceReq) domain.IdentitySource {
	src := domain.IdentitySource{
		ID:      req.ID,
		Name:    req.Name,
		Type:    domain.IdentitySourceType(req.Type),
		Enabled: req.Enabled,
	}

	if req.LDAP != nil {
		src.LDAPConfig = domain.LDAPConfig{
			URL:                  req.LDAP.URL,
			BaseDN:               req.LDAP.BaseDN,
			BindDN:               req.LDAP.BindDN,
			BindPassword:         req.LDAP.BindPassword,
			UsernameAttribute:    req.LDAP.UsernameAttribute,
			MailAttribute:        req.LDAP.MailAttribute,
			DisplayNameAttribute: req.LDAP.DisplayNameAttribute,
			TitleAttribute:       req.LDAP.TitleAttribute,
			UserFilter:           req.LDAP.UserFilter,
			SyncUserFilter:       req.LDAP.SyncUserFilter,
		}
	}

	if req.OIDC != nil {
		src.OIDCConfig = domain.OIDCConfig{
			Issuer:       req.OIDC.Issuer,
			ClientID:     req.OIDC.ClientID,
			ClientSecret: req.OIDC.ClientSecret,
			RedirectURI:  req.OIDC.RedirectURI,
			Scopes:       req.OIDC.Scopes,
			UserInfoURL:  req.OIDC.UserInfoURL,
			UserIDField:  req.OIDC.UserIDField,
			ProviderType: domain.OIDCProviderType(req.OIDC.ProviderType),
			AuthURL:      req.OIDC.AuthURL,
			TokenURL:     req.OIDC.TokenURL,
			Mapping: domain.Mapping{
				Username: req.OIDC.Mapping.Username,
				Email:    req.OIDC.Mapping.Email,
			},
		}
	}

	if req.Local != nil {
		src.LocalConfig = domain.LocalConfig{
			MinLength:         req.Local.MinLength,
			RequireDigit:      req.Local.RequireDigit,
			RequireUpper:      req.Local.RequireUpper,
			RequireLower:      req.Local.RequireLower,
			RequireSymbol:     req.Local.RequireSymbol,
			MaxFailedAttempts: req.Local.MaxFailedAttempts,
			LockoutDuration:   req.Local.LockoutDuration,
		}
	}

	if req.Passkey != nil {
		src.PasskeyConfig = domain.PasskeyConfig{
			RPID:                  req.Passkey.RPID,
			RPName:                req.Passkey.RPName,
			RPOrigins:             req.Passkey.RPOrigins,
			AttestationPreference: req.Passkey.AttestationPreference,
			UserVerification:      req.Passkey.UserVerification,
		}
	}

	return src
}

func (h *Handler) toVo(src domain.IdentitySource) IdentitySourceVO {
	vo := IdentitySourceVO{
		ID:      src.ID,
		Name:    src.Name,
		Type:    string(src.Type),
		Enabled: src.Enabled,
		Ctime:   src.Ctime,
		Utime:   src.Utime,
	}

	if src.Type == domain.LDAP {
		vo.LDAP = &LDAPVO{
			URL:                  src.LDAPConfig.URL,
			BaseDN:               src.LDAPConfig.BaseDN,
			BindDN:               src.LDAPConfig.BindDN,
			BindPassword:         "",
			UsernameAttribute:    src.LDAPConfig.UsernameAttribute,
			MailAttribute:        src.LDAPConfig.MailAttribute,
			DisplayNameAttribute: src.LDAPConfig.DisplayNameAttribute,
			TitleAttribute:       src.LDAPConfig.TitleAttribute,
			UserFilter:           src.LDAPConfig.UserFilter,
			SyncUserFilter:       src.LDAPConfig.SyncUserFilter,
		}
	}

	if src.Type == domain.OIDC {
		vo.OIDC = &OIDCVO{
			Issuer:       src.OIDCConfig.Issuer,
			ClientID:     src.OIDCConfig.ClientID,
			ClientSecret: "",
			RedirectURI:  src.OIDCConfig.RedirectURI,
			Scopes:       src.OIDCConfig.Scopes,
			UserInfoURL:  src.OIDCConfig.UserInfoURL,
			UserIDField:  src.OIDCConfig.UserIDField,
			ProviderType: string(src.OIDCConfig.ProviderType),
			AuthURL:      src.OIDCConfig.AuthURL,
			TokenURL:     src.OIDCConfig.TokenURL,
			Mapping: MappingVO{
				Username: src.OIDCConfig.Mapping.Username,
				Email:    src.OIDCConfig.Mapping.Email,
			},
		}
	}

	if src.Type == domain.LOCAL {
		vo.Local = &LocalVO{
			MinLength:         src.LocalConfig.MinLength,
			RequireDigit:      src.LocalConfig.RequireDigit,
			RequireUpper:      src.LocalConfig.RequireUpper,
			RequireLower:      src.LocalConfig.RequireLower,
			RequireSymbol:     src.LocalConfig.RequireSymbol,
			MaxFailedAttempts: src.LocalConfig.MaxFailedAttempts,
			LockoutDuration:   src.LocalConfig.LockoutDuration,
		}
	}

	if src.Type == domain.PASSKEY {
		vo.Passkey = &PasskeyVO{
			RPID:                  src.PasskeyConfig.RPID,
			RPName:                src.PasskeyConfig.RPName,
			RPOrigins:             src.PasskeyConfig.RPOrigins,
			AttestationPreference: src.PasskeyConfig.AttestationPreference,
			UserVerification:      src.PasskeyConfig.UserVerification,
		}
	}

	return vo
}
