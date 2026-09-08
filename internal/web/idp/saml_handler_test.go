package idp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	idpmocks "github.com/Duke1616/eiam/internal/service/idp/mocks"
	samlsvc "github.com/Duke1616/eiam/internal/service/idp/saml"
	samlmocks "github.com/Duke1616/eiam/internal/service/idp/saml/mocks"
	"github.com/crewjam/saml"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type SamlHandlerTestSuite struct {
	suite.Suite
	ctrl    *gomock.Controller
	appSvc  *idpmocks.MockIService
	samlSvc *samlmocks.MockISamlService
	server  *gin.Engine
}

func (s *SamlHandlerTestSuite) SetupTest() {
	session.SetDefaultProvider(&noopSessionProvider{})
	s.ctrl = gomock.NewController(s.T())
	s.appSvc = idpmocks.NewMockIService(s.ctrl)
	s.samlSvc = samlmocks.NewMockISamlService(s.ctrl)

	gin.SetMode(gin.TestMode)
	engine := gin.New()

	// 注入 Session 模拟中间件：
	// 默认登录态为 alice (uid=200, tenant_id=10)
	// 若带有 X-Anonymous: true 则视为未登录
	engine.Use(func(c *gin.Context) {
		if c.GetHeader("X-Anonymous") != "true" {
			sp := session.NewMemorySession(session.Claims{
				Uid: 200,
			})
			_ = sp.Set(c.Request.Context(), "username", "alice")
			_ = sp.Set(c.Request.Context(), "tenant_id", int64(10))
			c.Set("_session", sp)
		}
		c.Next()
	})

	hdl := NewHandler(s.appSvc, nil, nil, s.samlSvc)
	hdl.PublicRoutes(engine)
	hdl.PrivateRoutes(engine)
	s.server = engine
}

func (s *SamlHandlerTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *SamlHandlerTestSuite) TestSamlMetadata() {
	s.samlSvc.EXPECT().GetMetadataXML(gomock.Any(), gomock.Any()).
		Return("<EntityDescriptor>saml-metadata-content</EntityDescriptor>", nil)

	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	assert.Contains(s.T(), w.Header().Get("Content-Type"), "application/samlmetadata+xml")
	assert.Contains(s.T(), w.Body.String(), "saml-metadata-content")
}

func (s *SamlHandlerTestSuite) TestSamlSSO_MissingRequest() {
	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusBadRequest, w.Code)
	assert.Contains(s.T(), w.Body.String(), "缺少必要参数: SAMLRequest")
}

func (s *SamlHandlerTestSuite) TestSamlSSO_UnauthenticatedRedirect() {
	req := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest=dummy-req&RelayState=test-state", nil)
	req.Header.Set("X-Anonymous", "true") // 模拟未登录
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(s.T(), location, "/login?redirect=")
	assert.Contains(s.T(), location, url.QueryEscape("/saml/sso?SAMLRequest=dummy-req&RelayState=test-state"))
}

func (s *SamlHandlerTestSuite) TestSamlSSO_AuthenticatedSuccess_GET() {
	parsedAuthn := &saml.AuthnRequest{
		ID:                          "req-999",
		AssertionConsumerServiceURL: "https://sp.example.com/saml/acs",
		Issuer:                      &saml.Issuer{Value: "sp-client-id"},
	}

	s.samlSvc.EXPECT().ParseAuthnRequest("valid-base64-saml-req", true).
		Return(parsedAuthn, nil)

	s.samlSvc.EXPECT().BuildLoginResponse(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, req samlsvc.SamlLoginRequest) (*samlsvc.SamlLoginResult, error) {
			assert.Equal(s.T(), int64(200), req.UserID)
			assert.Equal(s.T(), int64(10), req.TenantID)
			assert.Equal(s.T(), "alice", req.Username)
			assert.Equal(s.T(), "test-relay-state", req.RelayState)
			return &samlsvc.SamlLoginResult{
				ACSURL:       "https://sp.example.com/saml/acs",
				SAMLResponse: "base64-signed-saml-response",
				RelayState:   req.RelayState,
			}, nil
		})

	req := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest=valid-base64-saml-req&RelayState=test-relay-state", nil)
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(s.T(), body, "<form method=\"post\" action=\"https://sp.example.com/saml/acs\">")
	assert.Contains(s.T(), body, "<input type=\"hidden\" name=\"SAMLResponse\" value=\"base64-signed-saml-response\" />")
	assert.Contains(s.T(), body, "<input type=\"hidden\" name=\"RelayState\" value=\"test-relay-state\" />")
}

func (s *SamlHandlerTestSuite) TestSamlSSO_AuthenticatedSuccess_POST() {
	parsedAuthn := &saml.AuthnRequest{
		ID:     "post-req-123",
		Issuer: &saml.Issuer{Value: "sp-client-id"},
	}

	s.samlSvc.EXPECT().ParseAuthnRequest("post-saml-req", false).
		Return(parsedAuthn, nil)

	s.samlSvc.EXPECT().BuildLoginResponse(gomock.Any(), gomock.Any()).
		Return(&samlsvc.SamlLoginResult{
			ACSURL:       "https://sp.example.com/acs",
			SAMLResponse: "signed-response",
			RelayState:   "post-relay",
		}, nil)

	formData := url.Values{
		"SAMLRequest": {"post-saml-req"},
		"RelayState":  {"post-relay"},
	}
	req := httptest.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(s.T(), body, "https://sp.example.com/acs")
	assert.Contains(s.T(), body, "signed-response")
}

func (s *SamlHandlerTestSuite) TestSamlIdPInitiatedLogin() {
	app := domain.Application{
		ID:           88,
		TenantID:     10,
		Protocol:     domain.ProtocolSAML,
		ClientID:     "jumpserver-saml",
		RedirectURIs: []string{"https://jumpserver.example.com/core/auth/saml2/acs/"},
	}

	s.appSvc.EXPECT().GetByID(gomock.Any(), int64(88)).Return(app, nil)
	s.samlSvc.EXPECT().BuildLoginResponse(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, req samlsvc.SamlLoginRequest) (*samlsvc.SamlLoginResult, error) {
			assert.Equal(s.T(), "jumpserver-saml", req.ClientID)
			assert.Equal(s.T(), "https://jumpserver.example.com/core/auth/saml2/acs/", req.ACSURL)
			return &samlsvc.SamlLoginResult{
				ACSURL:       req.ACSURL,
				SAMLResponse: "jumpserver-saml-resp",
			}, nil
		})

	req := httptest.NewRequest(http.MethodGet, "/saml/login/88", nil)
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(s.T(), body, "action=\"https://jumpserver.example.com/core/auth/saml2/acs/\"")
	assert.Contains(s.T(), body, "value=\"jumpserver-saml-resp\"")
}

func (s *SamlHandlerTestSuite) TestSamlCertificate() {
	fakeCert := "-----BEGIN CERTIFICATE-----\nMIIC...FAKE...\n-----END CERTIFICATE-----\n"
	s.samlSvc.EXPECT().GetCertificatePEM().Return(fakeCert)

	req := httptest.NewRequest(http.MethodGet, "/saml/certificate", nil)
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	assert.Contains(s.T(), w.Header().Get("Content-Type"), "application/x-x509-ca-cert")
	assert.Contains(s.T(), w.Header().Get("Content-Disposition"), "attachment; filename=\"idp-certificate.crt\"")
	assert.Equal(s.T(), fakeCert, w.Body.String())
}

func (s *SamlHandlerTestSuite) TestSamlDescriptor() {
	fakeDetail := samlsvc.CertificateDetail{
		PEM:         "-----BEGIN CERTIFICATE-----\nMIIC...FAKE...\n-----END CERTIFICATE-----\n",
		Fingerprint: "AA:BB:CC:DD:EE",
		Subject:     "EIAM SAML Identity Provider",
		NotBefore:   "2026-01-01T00:00:00Z",
		NotAfter:    "2029-01-01T00:00:00Z",
	}
	s.samlSvc.EXPECT().GetCertificateDetail().Return(fakeDetail)

	req := httptest.NewRequest(http.MethodGet, "/api/idp/saml/descriptor", nil)
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(s.T(), body, "\"code\":0")
	assert.Contains(s.T(), body, "/saml/metadata")
	assert.Contains(s.T(), body, "/saml/sso")
	assert.Contains(s.T(), body, "/saml/certificate")
	assert.Contains(s.T(), body, "MIIC...FAKE...")
	assert.Contains(s.T(), body, "AA:BB:CC:DD:EE")
	assert.Contains(s.T(), body, "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
}

func (s *SamlHandlerTestSuite) TestSamlRotateCertificate() {
	newFakeDetail := &samlsvc.CertificateDetail{
		PEM:         "-----BEGIN CERTIFICATE-----\nMIIC...NEW_ROTATED_CERT...\n-----END CERTIFICATE-----\n",
		Fingerprint: "11:22:33:44:55",
		Subject:     "EIAM SAML Identity Provider",
		NotBefore:   "2026-01-01T00:00:00Z",
		NotAfter:    "2031-01-01T00:00:00Z",
	}
	s.samlSvc.EXPECT().RotateCertificate(gomock.Any(), 5).Return(newFakeDetail, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/idp/saml/certificate/rotate", strings.NewReader(`{"validity_years":5}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.server.ServeHTTP(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(s.T(), body, "\"code\":0")
	assert.Contains(s.T(), body, "NEW_ROTATED_CERT")
	assert.Contains(s.T(), body, "11:22:33:44:55")
}

func TestSamlHandlerSuite(t *testing.T) {
	suite.Run(t, new(SamlHandlerTestSuite))
}
