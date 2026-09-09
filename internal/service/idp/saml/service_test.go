package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository/cache"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	"github.com/Duke1616/eiam/internal/service/idp/claims"
	claimsmocks "github.com/Duke1616/eiam/internal/service/idp/claims/mocks"
	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type fakeSamlCache struct {
	cert *cache.SamlClusterCertificate
}

func (f *fakeSamlCache) GetOrSetClusterCertificate(ctx context.Context, certID string, generateFn func() (*cache.SamlClusterCertificate, error)) (*cache.SamlClusterCertificate, error) {
	if f.cert != nil {
		return f.cert, nil
	}
	c, err := generateFn()
	if err == nil {
		f.cert = c
	}
	return c, err
}

func (f *fakeSamlCache) SetClusterCertificate(ctx context.Context, certID string, cert *cache.SamlClusterCertificate) error {
	f.cert = cert
	return nil
}

func TestSamlService_GetMetadataXML(t *testing.T) {
	certMgr, err := NewClusterCertificateManager(context.Background(), "", "", 1095, &fakeSamlCache{})
	require.NoError(t, err)

	svc := NewSamlService(certMgr, nil, nil)
	xmlStr, err := svc.GetMetadataXML(context.Background(), "https://iam.example.com")
	require.NoError(t, err)
	assert.Contains(t, xmlStr, "entityID=\"https://iam.example.com/saml/metadata\"")
	assert.Contains(t, xmlStr, "Location=\"https://iam.example.com/saml/sso\"")
	assert.Contains(t, xmlStr, certMgr.CertificateBase64DER())

	// 验证 XML 结构合法
	var ed saml.EntityDescriptor
	err = xml.Unmarshal([]byte(xmlStr), &ed)
	require.NoError(t, err)
	assert.Equal(t, "https://iam.example.com/saml/metadata", ed.EntityID)
	require.Len(t, ed.IDPSSODescriptors, 1)
}

func TestSamlService_ParseAuthnRequest(t *testing.T) {
	authn := saml.AuthnRequest{
		ID:                          "test-request-id-123",
		Version:                     "2.0",
		AssertionConsumerServiceURL: "https://sp.example.com/saml/acs",
		Issuer: &saml.Issuer{
			Value: "https://sp.example.com/metadata",
		},
	}
	rawXML, err := xml.Marshal(authn)
	require.NoError(t, err)

	// 1. 测试 HTTP-POST Binding (纯 Base64)
	postEncoded := base64.StdEncoding.EncodeToString(rawXML)
	svc := NewSamlService(nil, nil, nil)
	parsedPost, err := svc.ParseAuthnRequest(postEncoded, false)
	require.NoError(t, err)
	assert.Equal(t, "test-request-id-123", parsedPost.ID)
	assert.Equal(t, "https://sp.example.com/saml/acs", parsedPost.AssertionConsumerServiceURL)
	assert.Equal(t, "https://sp.example.com/metadata", parsedPost.Issuer.Value)

	// 2. 测试 HTTP-Redirect Binding (Deflate + Base64)
	var buf bytes.Buffer
	flateWriter, err := flate.NewWriter(&buf, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = flateWriter.Write(rawXML)
	require.NoError(t, err)
	require.NoError(t, flateWriter.Close())
	redirectEncoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	parsedRedirect, err := svc.ParseAuthnRequest(redirectEncoded, true)
	require.NoError(t, err)
	assert.Equal(t, "test-request-id-123", parsedRedirect.ID)
	assert.Equal(t, "https://sp.example.com/metadata", parsedRedirect.Issuer.Value)

	// 3. 测试空请求报错
	_, err = svc.ParseAuthnRequest("", false)
	assert.ErrorIs(t, err, errs.ErrSamlInvalidRequest)
}

func TestSamlService_BuildLoginResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	certMgr, err := NewClusterCertificateManager(context.Background(), "", "", 1095, &fakeSamlCache{})
	require.NoError(t, err)

	claimsResolver := claimsmocks.NewMockIClaimsResolver(ctrl)
	appRepo := repomocks.NewMockIApplicationRepository(ctrl)

	svc := NewSamlService(certMgr, claimsResolver, appRepo)
	ctx := context.Background()

	testCases := []struct {
		name       string
		req        SamlLoginRequest
		mock       func()
		wantErr    error
		verifyResp func(t *testing.T, res *SamlLoginResult)
	}{
		{
			name: "应用未在白名单中注册",
			req: SamlLoginRequest{
				ClientID: "unknown-sp",
			},
			mock: func() {
				appRepo.EXPECT().FindByClientID(gomock.Any(), "unknown-sp").
					Return(domain.Application{}, errs.ErrApplicationNotFound)
			},
			wantErr: errs.ErrSamlIssuerNotRegistered,
		},
		{
			name: "应用未开启 SAML 协议支持",
			req: SamlLoginRequest{
				ClientID: "oidc-only-app",
			},
			mock: func() {
				appRepo.EXPECT().FindByClientID(gomock.Any(), "oidc-only-app").
					Return(domain.Application{
						ClientID: "oidc-only-app",
						Name:     "纯 OIDC 客户端",
						Protocol: domain.ProtocolOIDC,
					}, nil)
			},
			wantErr: errs.ErrUnsupportedProtocol,
		},
		{
			name: "请求的回调 ACS 地址不在白名单中",
			req: SamlLoginRequest{
				ClientID: "alicloud-ram-sso",
				ACSURL:   "https://hacker.com/acs",
			},
			mock: func() {
				appRepo.EXPECT().FindByClientID(gomock.Any(), "alicloud-ram-sso").
					Return(domain.Application{
						ClientID:     "alicloud-ram-sso",
						Protocol:     domain.ProtocolSAML,
						RedirectURIs: []string{"https://signin.aliyun.com/saml-role/sso"},
					}, nil)
			},
			wantErr: errs.ErrSamlInvalidACSURL,
		},
		{
			name: "成功生成签名 SAMLResponse 并通过 XML-DSig 验签",
			req: SamlLoginRequest{
				UserID:     1001,
				TenantID:   1,
				Username:   "alex",
				ClientID:   "gitlab-enterprise",
				ACSURL:     "https://gitlab.example.com/users/auth/saml/callback",
				RelayState: "state-token-xyz",
				IssuerURL:  "https://iam.example.com",
			},
			mock: func() {
				appRepo.EXPECT().FindByClientID(gomock.Any(), "gitlab-enterprise").
					Return(domain.Application{
						ClientID:     "gitlab-enterprise",
						Protocol:     domain.ProtocolSAML,
						RedirectURIs: []string{"https://gitlab.example.com/users/auth/saml/callback"},
					}, nil)

				claimsResolver.EXPECT().Resolve(gomock.Any(), claims.IdentityRef{
					TenantID: 1,
					UserID:   1001,
					Username: "alex",
				}).Return(claims.Claims{
					Subject:  "1001",
					UserID:   1001,
					Username: "alex",
					Name:     "Alex Morgan",
					Email:    "alex@example.com",
					TenantID: 1,
					Roles:    []string{"admin", "developer"},
				}, nil)
			},
			wantErr: nil,
			verifyResp: func(t *testing.T, res *SamlLoginResult) {
				require.NotNil(t, res)
				assert.Equal(t, "https://gitlab.example.com/users/auth/saml/callback", res.ACSURL)
				assert.Equal(t, "state-token-xyz", res.RelayState)

				// 校验 Base64 解码与 XML
				xmlBytes, decodeErr := base64.StdEncoding.DecodeString(res.SAMLResponse)
				require.NoError(t, decodeErr)

				doc := etree.NewDocument()
				err := doc.ReadFromBytes(xmlBytes)
				require.NoError(t, err)

				// 验证 Assertion 与 XML-DSig 签名节点存在
				assertionEl := doc.Root().FindElement(".//Assertion")
				require.NotNil(t, assertionEl)

				sigEl := assertionEl.FindElement(".//Signature")
				require.NotNil(t, sigEl)

				// 使用公钥证书验签
				valCtx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
					Roots: []*x509.Certificate{certMgr.Certificate()},
				})
				validatedEl, valErr := valCtx.Validate(assertionEl)
				require.NoError(t, valErr, "生成的 SAML Assertion XML-DSig 签名必须验证通过")
				assert.NotNil(t, validatedEl)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.mock()
			res, err := svc.BuildLoginResponse(ctx, tc.req)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
				tc.verifyResp(t, res)
			}
		})
	}
}
