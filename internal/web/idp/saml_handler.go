package idp

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	samlsvc "github.com/Duke1616/eiam/internal/service/idp/saml"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
)

// SamlDescriptorVO SAML 接入端点与证书描述符视图对象
type SamlDescriptorVO struct {
	EntityID               string   `json:"entity_id"`
	SSOURL                 string   `json:"sso_url"`
	MetadataURL            string   `json:"metadata_url"`
	CertificateURL         string   `json:"certificate_url"`
	CertificatePEM         string   `json:"certificate_pem"`
	CertificateFingerprint string   `json:"certificate_fingerprint"`
	CertificateSubject     string   `json:"certificate_subject"`
	NotBefore              string   `json:"not_before"`
	NotAfter               string   `json:"not_after"`
	BindingTypes           []string `json:"binding_types"`
	NameIDFormat           string   `json:"name_id_format"`
}

// SamlMetadata 输出标准 SAML 2.0 IdP 元数据 XML (GET /saml/metadata)
func (h *Handler) SamlMetadata(c *gin.Context) {
	issuerURL := h.resolveIssuerURL(c)
	metadataXML, err := h.samlSvc.GetMetadataXML(c.Request.Context(), issuerURL)
	if err != nil {
		h.logger.Error("生成 SAML Metadata 失败", elog.FieldErr(err))
		c.String(http.StatusInternalServerError, "生成元数据失败")
		return
	}

	c.Header("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	c.String(http.StatusOK, metadataXML)
}

// SamlCertificate 导出当前 IdP 生效的 X.509 签名证书文件 (GET /saml/certificate)
// 支持浏览器与 SP 直接下载标准 .crt 文件
func (h *Handler) SamlCertificate(c *gin.Context) {
	certPEM := h.samlSvc.GetCertificatePEM()
	if certPEM == "" {
		c.String(http.StatusNotFound, "证书不存在")
		return
	}

	c.Header("Content-Type", "application/x-x509-ca-cert; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename=\"idp-certificate.crt\"")
	c.String(http.StatusOK, certPEM)
}

// SamlDescriptor 为租户管理控制台提供 SAML 接入配置详情 (GET /api/idp/saml/descriptor)
// 归属于 PrivateRoutes，需登录态与租户权限保护
func (h *Handler) SamlDescriptor(ctx *ginx.Context) (ginx.Result, error) {
	issuerURL := strings.TrimRight(h.resolveIssuerURL(ctx.Context), "/")
	certDetail := h.samlSvc.GetCertificateDetail()

	return ginx.Result{
		Data: SamlDescriptorVO{
			EntityID:               fmt.Sprintf("%s/saml/metadata", issuerURL),
			SSOURL:                 fmt.Sprintf("%s/saml/sso", issuerURL),
			MetadataURL:            fmt.Sprintf("%s/saml/metadata", issuerURL),
			CertificateURL:         fmt.Sprintf("%s/saml/certificate", issuerURL),
			CertificatePEM:         certDetail.PEM,
			CertificateFingerprint: certDetail.Fingerprint,
			CertificateSubject:     certDetail.Subject,
			NotBefore:              certDetail.NotBefore,
			NotAfter:               certDetail.NotAfter,
			BindingTypes:           []string{"HTTP-Redirect", "HTTP-POST"},
			NameIDFormat:           "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		},
	}, nil
}

// RotateCertificateReq 证书轮换请求入参
type RotateCertificateReq struct {
	ValidityYears int `json:"validity_years"`
}

// SamlRotateCertificate 重新生成并轮换 SAML X.509 证书 (POST /api/idp/saml/certificate/rotate)
func (h *Handler) SamlRotateCertificate(ctx *ginx.Context, req RotateCertificateReq) (ginx.Result, error) {
	detail, err := h.samlSvc.RotateCertificate(ctx.Request.Context(), req.ValidityYears)
	if err != nil {
		h.logger.Error("轮换 SAML 证书失败", elog.FieldErr(err))
		return ginx.Result{Code: 500, Msg: "轮换证书失败: " + err.Error()}, err
	}

	issuerURL := strings.TrimRight(h.resolveIssuerURL(ctx.Context), "/")
	return ginx.Result{
		Data: SamlDescriptorVO{
			EntityID:               fmt.Sprintf("%s/saml/metadata", issuerURL),
			SSOURL:                 fmt.Sprintf("%s/saml/sso", issuerURL),
			MetadataURL:            fmt.Sprintf("%s/saml/metadata", issuerURL),
			CertificateURL:         fmt.Sprintf("%s/saml/certificate", issuerURL),
			CertificatePEM:         detail.PEM,
			CertificateFingerprint: detail.Fingerprint,
			CertificateSubject:     detail.Subject,
			NotBefore:              detail.NotBefore,
			NotAfter:               detail.NotAfter,
			BindingTypes:           []string{"HTTP-Redirect", "HTTP-POST"},
			NameIDFormat:           "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		},
	}, nil
}

// SamlSSO 处理 SP-Initiated SSO 认证与断言签发端点 (GET /saml/sso 与 POST /saml/sso)
// 支持 HTTP-Redirect (GET) 与 HTTP-POST (POST) 两种 SAML 2.0 绑定协议
func (h *Handler) SamlSSO(c *gin.Context) {
	isRedirect := c.Request.Method == http.MethodGet

	var samlRequest, relayState string
	if isRedirect {
		samlRequest = c.Query("SAMLRequest")
		relayState = c.Query("RelayState")
	} else {
		samlRequest = c.PostForm("SAMLRequest")
		relayState = c.PostForm("RelayState")
	}

	if strings.TrimSpace(samlRequest) == "" {
		c.String(http.StatusBadRequest, "缺少必要参数: SAMLRequest")
		return
	}

	// 1. 检查当前主站 Session 登录态并自动拦截未登录
	userSess, ok := h.requireAuth(c)
	if !ok {
		return
	}

	// 2. 用户已登录，解析 AuthnRequest
	authnReq, err := h.samlSvc.ParseAuthnRequest(samlRequest, isRedirect)
	if err != nil {
		h.logger.Warn("解析 SAMLRequest 失败", elog.FieldErr(err))
		c.String(http.StatusBadRequest, fmt.Sprintf("非法的 SAMLRequest: %v", err))
		return
	}

	// 3. 调用 Service 生成已签名的 SAMLResponse
	issuerURL := h.resolveIssuerURL(c)

	result, err := h.samlSvc.BuildLoginResponse(c.Request.Context(), samlsvc.SamlLoginRequest{
		UserID:       userSess.UserID,
		TenantID:     userSess.TenantID,
		Username:     userSess.Username,
		AuthnRequest: authnReq,
		RelayState:   relayState,
		IssuerURL:    issuerURL,
	})
	if err != nil {
		if errors.Is(err, errs.ErrSamlIssuerNotRegistered) || errors.Is(err, errs.ErrSamlInvalidACSURL) {
			c.String(http.StatusForbidden, err.Error())
			return
		}
		h.logger.Error("生成 SAML 断言响应失败", elog.FieldErr(err))
		c.String(http.StatusInternalServerError, "签发单点登录断言失败")
		return
	}

	// 4. 渲染标准 HTTP-POST Binding 自动提交表单，将 SAMLResponse 回传给 SP
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, renderAutoSubmitForm(result.ACSURL, result.SAMLResponse, result.RelayState))
}

// SamlIdPInitiatedLogin 处理由 EIAM 门户一键发起的 IdP-Initiated SSO 登录 (GET /saml/login/:id)
func (h *Handler) SamlIdPInitiatedLogin(c *gin.Context) {
	appIDStr := c.Param("id")
	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil || appID <= 0 {
		c.String(http.StatusBadRequest, "非法的应用 ID")
		return
	}

	// 1. 检查主站登录态并自动拦截未登录
	userSess, ok := h.requireAuth(c)
	if !ok {
		return
	}

	// 2. 检索应用
	app, err := h.appSvc.GetByID(c.Request.Context(), appID)
	if err != nil {
		c.String(http.StatusNotFound, "目标接入应用不存在")
		return
	}

	if !app.Protocol.IsSAML() && app.Protocol != domain.Protocol("") {
		c.String(http.StatusBadRequest, "目标应用不是 SAML 2.0 协议类型")
		return
	}

	if len(app.RedirectURIs) == 0 {
		c.String(http.StatusBadRequest, "目标应用未配置 ACS 回调地址")
		return
	}

	issuerURL := h.resolveIssuerURL(c)

	result, err := h.samlSvc.BuildLoginResponse(c.Request.Context(), samlsvc.SamlLoginRequest{
		UserID:    userSess.UserID,
		TenantID:  userSess.TenantID,
		Username:  userSess.Username,
		ClientID:  app.ClientID,
		ACSURL:    app.RedirectURIs[0],
		IssuerURL: issuerURL,
	})
	if err != nil {
		h.logger.Error("IdP-Initiated SSO 签发失败", elog.FieldErr(err))
		c.String(http.StatusInternalServerError, "签发单点登录断言失败")
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, renderAutoSubmitForm(result.ACSURL, result.SAMLResponse, result.RelayState))
}

// renderAutoSubmitForm 渲染符合 SAML 2.0 规范的纯原生自动提交 HTML 表单
func renderAutoSubmitForm(acsURL, samlResponse, relayState string) string {
	escapedACS := html.EscapeString(acsURL)
	escapedSAMLResponse := html.EscapeString(samlResponse)
	escapedRelayState := html.EscapeString(relayState)

	relayStateInput := ""
	if escapedRelayState != "" {
		relayStateInput = fmt.Sprintf("\n      <input type=\"hidden\" name=\"RelayState\" value=\"%s\" />", escapedRelayState)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>正在跳转至单点登录目标系统...</title>
</head>
<body onload="document.forms[0].submit()">
  <noscript>
    <p>正在跳转，如果页面未自动跳转，请点击下方按钮继续：</p>
  </noscript>
  <form method="post" action="%s">
    <input type="hidden" name="SAMLResponse" value="%s" />%s
    <noscript>
      <button type="submit">继续跳转</button>
    </noscript>
  </form>
</body>
</html>`, escapedACS, escapedSAMLResponse, relayStateInput)
}
