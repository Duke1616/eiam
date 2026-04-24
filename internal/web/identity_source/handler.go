package identity_source

import (
	"github.com/Duke1616/eiam/internal/domain"
	idsvc "github.com/Duke1616/eiam/internal/service/identity_source"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ekit/slice"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	capability.IRegistry
	svc idsvc.IService
}

func NewHandler(svc idsvc.IService) *Handler {
	return &Handler{
		svc:       svc,
		IRegistry: capability.NewRegistry("iam", "identity_source", "身份源管理"),
	}
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
	g.POST("/test", h.Capability("测试身份源连接", "test").
		Handle(ginx.B[SaveIdentitySourceReq](h.Test)),
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
		Data: slice.Map(sources, func(idx int, src domain.IdentitySource) IdentitySourceVO {
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
			UserFilter:           req.LDAP.UserFilter,
			SyncUserFilter:       req.LDAP.SyncUserFilter,
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
			BindPassword:         "******",
			UsernameAttribute:    src.LDAPConfig.UsernameAttribute,
			MailAttribute:        src.LDAPConfig.MailAttribute,
			DisplayNameAttribute: src.LDAPConfig.DisplayNameAttribute,
			UserFilter:           src.LDAPConfig.UserFilter,
			SyncUserFilter:       src.LDAPConfig.SyncUserFilter,
		}
	}

	return vo
}
