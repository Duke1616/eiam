package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/idp/claims"
	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/gotomicro/ego/core/elog"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	defaultAssertionValidity  = 5 * time.Minute
	defaultClockSkewTolerance = 1 * time.Minute
	maxSAMLRequestSize        = 1 << 20 // 1MB 安全读取上限，防御 Deflate 压缩炸弹 DoS

	samlProtocolSAML2       = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlBearerConfirmation  = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	samlAuthnContextPW      = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	nameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	nameIDFormatEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	nameIDFormatPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// buildIdPEntityID 统一构造 IdP 唯一实体标识 (规范固定为 <base_url>/saml/metadata)
func buildIdPEntityID(issuerURL string) string {
	return fmt.Sprintf("%s/saml/metadata", strings.TrimRight(issuerURL, "/"))
}

// buildSSOURL 统一构造 IdP 单点登录接入端点 (规范固定为 <base_url>/saml/sso)
func buildSSOURL(issuerURL string) string {
	return fmt.Sprintf("%s/saml/sso", strings.TrimRight(issuerURL, "/"))
}

// SamlLoginRequest SAML 单点登录请求入参
type SamlLoginRequest struct {
	UserID       int64              // 已登录用户 ID
	TenantID     int64              // 用户当前生效租户 ID
	Username     string             // 用户名
	ClientID     string             // SP EntityID (为空时从 AuthnRequest 解析)
	ACSURL       string             // 断言消费地址 (为空时取应用默认配置)
	RelayState   string             // SP 透传的状态凭证
	AuthnRequest *saml.AuthnRequest // 已解析的 SP 认证请求对象 (可选)
	IssuerURL    string             // IdP 服务根路径 (用于构建 IdP EntityID)
}

// SamlLoginResult SAML 单点登录签发结果
type SamlLoginResult struct {
	ACSURL       string // 目标回调 ACS 端点
	SAMLResponse string // Base64 编码的已签名 XML-DSig SAMLResponse
	RelayState   string // 透传回 SP 的 RelayState
}

// CertificateDetail X.509 证书元数据详情
type CertificateDetail struct {
	PEM         string `json:"pem"`
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
}

// ISamlService SAML 2.0 身份提供商核心协议服务接口
//
//go:generate mockgen -source=./service.go -package=samlmocks -destination=./mocks/service.mock.go -typed ISamlService
type ISamlService interface {
	// GetMetadataXML 生成标准 SAML 2.0 IdP 元数据 XML (EntityDescriptor)
	GetMetadataXML(ctx context.Context, issuerURL string) (string, error)
	// ParseAuthnRequest 解析 HTTP-Redirect 或 HTTP-POST 传入的原始 SAMLRequest 字符串
	ParseAuthnRequest(rawReq string, isRedirect bool) (*saml.AuthnRequest, error)
	// BuildLoginResponse 校验目标 SP 应用并构造包含数字签名的 SAMLResponse 凭证
	BuildLoginResponse(ctx context.Context, req SamlLoginRequest) (*SamlLoginResult, error)
	// GetCertificatePEM 导出当前 IdP 生效的 X.509 公钥证书 PEM 文本 (供下载或 SP 手动导入)
	GetCertificatePEM() string
	// GetCertificateDetail 导出当前生效的 X.509 证书元数据详情 (含指纹、有效期、主题等)
	GetCertificateDetail() CertificateDetail
	// RotateCertificate 重新生成并轮换 X.509 证书与签名私钥 (支持传入自定义有效期年限)
	RotateCertificate(ctx context.Context, validityYears int) (*CertificateDetail, error)
}

type samlService struct {
	certMgr        ICertificateManager
	claimsResolver claims.IClaimsResolver
	appRepo        repository.IApplicationRepository
	logger         *elog.Component
}

// NewSamlService 构造 SAML 核心协议服务实例
func NewSamlService(
	certMgr ICertificateManager,
	claimsResolver claims.IClaimsResolver,
	appRepo repository.IApplicationRepository,
) ISamlService {
	return &samlService{
		certMgr:        certMgr,
		claimsResolver: claimsResolver,
		appRepo:        appRepo,
		logger:         elog.DefaultLogger,
	}
}

// GetCertificatePEM 导出当前 IdP 生效的 X.509 公钥证书 PEM 文本
func (s *samlService) GetCertificatePEM() string {
	return s.certMgr.CertificatePEM()
}

// GetMetadataXML 构造标准的 SAML 2.0 IdP 元数据 XML 文档
func (s *samlService) GetMetadataXML(ctx context.Context, issuerURL string) (string, error) {
	idpEntityID := buildIdPEntityID(issuerURL)
	ssoURL := buildSSOURL(issuerURL)

	ed := saml.EntityDescriptor{
		EntityID: idpEntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: samlProtocolSAML2,
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{Data: s.certMgr.CertificateBase64DER()},
										},
									},
								},
							},
						},
					},
					NameIDFormats: []saml.NameIDFormat{
						nameIDFormatUnspecified,
						nameIDFormatEmail,
						nameIDFormatPersistent,
					},
				},
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: ssoURL,
					},
					{
						Binding:  saml.HTTPPostBinding,
						Location: ssoURL,
					},
				},
			},
		},
	}

	data, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化 SAML Metadata 失败: %w", err)
	}

	return fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n%s", string(data)), nil
}

// ParseAuthnRequest 解析 HTTP-Redirect 或 HTTP-POST 传入的原始 SAMLRequest
func (s *samlService) ParseAuthnRequest(rawReq string, isRedirect bool) (*saml.AuthnRequest, error) {
	rawReq = strings.TrimSpace(rawReq)
	if rawReq == "" {
		return nil, errs.ErrSamlInvalidRequest
	}

	data, err := base64.StdEncoding.DecodeString(rawReq)
	if err != nil {
		return nil, fmt.Errorf("%w: Base64 解码失败: %v", errs.ErrSamlInvalidRequest, err)
	}

	var xmlData []byte
	if isRedirect {
		// HTTP-Redirect Binding: 必须使用 raw DEFLATE (RFC 1951) 解压缩
		reader := flate.NewReader(bytes.NewReader(data))
		defer reader.Close()
		// 防御解压炸弹 (Decompression Bomb / Zip Bomb DoS)，施加安全读取上限
		decompressed, readErr := io.ReadAll(io.LimitReader(reader, maxSAMLRequestSize))
		if readErr != nil {
			// 容错处理：部分非标准 SP 直接传递了未经 Deflate 压缩的原始 XML
			xmlData = data
		} else {
			xmlData = decompressed
		}
	} else {
		// HTTP-POST Binding: 无 Deflate 压缩
		xmlData = data
	}

	var authnReq saml.AuthnRequest
	if err = xml.Unmarshal(xmlData, &authnReq); err != nil {
		return nil, fmt.Errorf("%w: XML 解析为 AuthnRequest 失败: %v", errs.ErrSamlInvalidRequest, err)
	}

	return &authnReq, nil
}

// BuildLoginResponse 核心业务流水线：校验 SP -> 解析 Claims -> 组装断言 -> XML 签名
func (s *samlService) BuildLoginResponse(ctx context.Context, req SamlLoginRequest) (*SamlLoginResult, error) {
	// 1. 确定目标 SP 应用并校验回调 ACS 地址
	app, acsURL, err := s.resolveAndValidateSP(ctx, req)
	if err != nil {
		return nil, err
	}

	// 2. 解析用户完整身份声明与租户生效角色
	userClaims, err := s.claimsResolver.Resolve(ctx, claims.IdentityRef{
		TenantID: req.TenantID,
		UserID:   req.UserID,
		Username: req.Username,
	})
	if err != nil {
		return nil, fmt.Errorf("解析用户 Claims 属性失败: %w", err)
	}

	// 3. 组装符合 SAML 2.0 规范的 Response 与 Assertion 实体
	resp := s.buildSamlResponse(req, app.ClientID, acsURL, userClaims)

	// 4. 执行 XML-DSig 规范化与 RSA-SHA256 签名 (Enveloped Signature)
	signedXML, err := s.signResponse(&resp)
	if err != nil {
		s.logger.Error("SAML 断言签名生成失败", elog.FieldErr(err))
		return nil, fmt.Errorf("%w: %v", errs.ErrSamlSigningFailed, err)
	}

	return &SamlLoginResult{
		ACSURL:       acsURL,
		SAMLResponse: base64.StdEncoding.EncodeToString(signedXML),
		RelayState:   req.RelayState,
	}, nil
}

// resolveAndValidateSP 提取目标 SP EntityID 并校验应用合法性与 ACS URL 回调白名单
func (s *samlService) resolveAndValidateSP(ctx context.Context, req SamlLoginRequest) (domain.Application, string, error) {
	clientID := req.ClientID
	if clientID == "" && req.AuthnRequest != nil {
		clientID = req.AuthnRequest.Issuer.Value
	}
	if clientID == "" {
		return domain.Application{}, "", fmt.Errorf("%w: 无法识别请求中的 SP EntityID / ClientID", errs.ErrSamlIssuerNotRegistered)
	}

	app, err := s.appRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return domain.Application{}, "", fmt.Errorf("%w: client_id=%s", errs.ErrSamlIssuerNotRegistered, clientID)
	}

	if !app.SupportsProtocol(domain.ProtocolSAML) {
		return domain.Application{}, "", fmt.Errorf("%w: 应用 [%s] 未开启 SAML 2.0 协议支持", errs.ErrUnsupportedProtocol, app.Name)
	}

	acsURL := req.ACSURL
	if acsURL == "" && req.AuthnRequest != nil {
		acsURL = req.AuthnRequest.AssertionConsumerServiceURL
	}
	if acsURL == "" {
		if len(app.RedirectURIs) > 0 {
			acsURL = app.RedirectURIs[0]
		} else {
			return domain.Application{}, "", fmt.Errorf("%w: 应用未配置合法 ACS 回调地址白名单", errs.ErrSamlInvalidACSURL)
		}
	} else {
		if !app.HasRedirectURI(acsURL) {
			return domain.Application{}, "", fmt.Errorf("%w: acs_url=%s", errs.ErrSamlInvalidACSURL, acsURL)
		}
	}

	return app, acsURL, nil
}

// buildSamlResponse 组装 SAML 2.0 Response 及其内部包含的完整 Assertion 数据结构
func (s *samlService) buildSamlResponse(
	req SamlLoginRequest,
	clientID string,
	acsURL string,
	userClaims claims.Claims,
) saml.Response {
	now := time.Now().UTC()
	responseID := fmt.Sprintf("id_%s", uuid.New().String())
	assertionID := fmt.Sprintf("id_%s", uuid.New().String())
	idpEntityID := buildIdPEntityID(req.IssuerURL)

	inResponseTo := ""
	if req.AuthnRequest != nil {
		inResponseTo = req.AuthnRequest.ID
	}

	assertion := saml.Assertion{
		ID:           assertionID,
		IssueInstant: now,
		Version:      "2.0",
		Issuer: saml.Issuer{
			Value: idpEntityID,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format: nameIDFormatUnspecified,
				Value:  userClaims.Username,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: samlBearerConfirmation,
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						Recipient:    acsURL,
						NotOnOrAfter: now.Add(defaultAssertionValidity),
						InResponseTo: inResponseTo,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:    now.Add(-defaultClockSkewTolerance),
			NotOnOrAfter: now.Add(defaultAssertionValidity),
			AudienceRestrictions: []saml.AudienceRestriction{
				{
					Audience: saml.Audience{Value: clientID},
				},
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnInstant: now,
				SessionIndex: assertionID,
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: samlAuthnContextPW,
					},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: userClaims.ToSAMLAttributes(),
			},
		},
	}

	return saml.Response{
		ID:           responseID,
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  acsURL,
		Issuer: &saml.Issuer{
			Value: idpEntityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		},
		Assertion: &assertion,
	}
}

// signResponse 使用标准 W3C XML-DSig 对 Assertion 执行数字签名
func (s *samlService) signResponse(resp *saml.Response) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(resp.Element())

	assertionEl := doc.Root().FindElement(".//Assertion")
	if assertionEl == nil {
		return nil, errors.New("无法在 SAML 响应中定位 Assertion 节点")
	}

	sigCtx, err := dsig.NewSigningContext(s.certMgr.PrivateKey(), [][]byte{s.certMgr.Certificate().Raw})
	if err != nil {
		return nil, fmt.Errorf("构造 XML 签名上下文失败: %w", err)
	}
	sigCtx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// 生成 Enveloped 签名
	sig, err := sigCtx.ConstructSignature(assertionEl, true)
	if err != nil {
		return nil, fmt.Errorf("生成 Assertion XML 签名失败: %w", err)
	}

	// SAML 2.0 规范约束：<ds:Signature> 必须插入在 <saml:Issuer> 之后，<saml:Subject> 之前
	issuerEl := assertionEl.FindElement("Issuer")
	if issuerEl != nil {
		idx := issuerEl.Index()
		assertionEl.InsertChildAt(idx+1, sig)
	} else {
		assertionEl.InsertChildAt(0, sig)
	}

	return doc.WriteToBytes()
}

func (s *samlService) GetCertificateDetail() CertificateDetail {
	return s.certMgr.Detail()
}

func (s *samlService) RotateCertificate(ctx context.Context, validityYears int) (*CertificateDetail, error) {
	return s.certMgr.RotateCertificate(ctx, validityYears)
}
