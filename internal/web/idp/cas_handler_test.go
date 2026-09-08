package idp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	casmocks "github.com/Duke1616/eiam/internal/service/idp/cas/mocks"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

// CasHandlerTestSuite 基于 httptest 覆盖 CAS 协议所有端点的 Web 集成测试套件
type CasHandlerTestSuite struct {
	suite.Suite
	ctrl   *gomock.Controller
	casSvc *casmocks.MockICasService
	server *gin.Engine
}

func (s *CasHandlerTestSuite) SetupTest() {
	session.SetDefaultProvider(&noopSessionProvider{})
	s.ctrl = gomock.NewController(s.T())
	s.casSvc = casmocks.NewMockICasService(s.ctrl)

	gin.SetMode(gin.TestMode)
	engine := gin.New()

	// 统一注入 Session 中间件：默认注入 alice (uid=100, tenant_id=1) 登录态
	// 若请求头包含 X-Anonymous: true 则跳过注入以模拟未登录访问
	engine.Use(func(c *gin.Context) {
		if c.GetHeader("X-Anonymous") != "true" {
			sp := session.NewMemorySession(session.Claims{
				Uid: 100,
			})
			_ = sp.Set(c.Request.Context(), "username", "alice")
			_ = sp.Set(c.Request.Context(), "tenant_id", int64(1))
			c.Set("_session", sp)
		}
		c.Next()
	})

	hdl := NewHandler(nil, nil, s.casSvc)
	hdl.PublicRoutes(engine)
	s.server = engine
}

func (s *CasHandlerTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

// --- 1. CasLogin 端点测试 (GET /cas/login) ---

func (s *CasHandlerTestSuite) TestCasLogin() {
	testCases := []struct {
		name         string
		targetURL    string
		isAnonymous  bool
		mockSetup    func()
		wantCode     int
		wantLocation string
		wantBody     string
	}{
		{
			name:      "缺少 service 参数返回 400",
			targetURL: "/cas/login",
			mockSetup: func() {},
			wantCode:  http.StatusBadRequest,
			wantBody:  "缺少必要参数: service",
		},
		{
			name:      "service 不是绝对 URL 返回 400",
			targetURL: "/cas/login?service=/relative/path",
			mockSetup: func() {},
			wantCode:  http.StatusBadRequest,
			wantBody:  "非法的目标服务地址 (service 必须为完整绝对 URL)",
		},
		{
			name:        "未登录访问跳转登录页",
			targetURL:   "/cas/login?service=" + url.QueryEscape("https://jumpserver.example.com/callback"),
			isAnonymous: true,
			mockSetup:   func() {},
			wantCode:    http.StatusFound,
			wantLocation: "/login?redirect=" + url.QueryEscape("/cas/login?service="+url.QueryEscape("https://jumpserver.example.com/callback")),
		},
		{
			name:        "未登录但带 gateway=true 规范直跳目标服务",
			targetURL:   "/cas/login?gateway=true&service=" + url.QueryEscape("https://jumpserver.example.com/callback"),
			isAnonymous: true,
			mockSetup:   func() {},
			wantCode:    http.StatusFound,
			wantLocation: "https://jumpserver.example.com/callback",
		},
		{
			name:      "已登录成功签发 ST 票据并重定向回目标系统",
			targetURL: "/cas/login?service=" + url.QueryEscape("https://jumpserver.example.com/callback"),
			mockSetup: func() {
				s.casSvc.EXPECT().
					GenerateTicket(gomock.Any(), int64(100), int64(1), "alice", "https://jumpserver.example.com/callback").
					Return("ST-987654321", nil)
			},
			wantCode:     http.StatusFound,
			wantLocation: "https://jumpserver.example.com/callback?ticket=ST-987654321",
		},
		{
			name:      "目标服务未在白名单中注册返回 403",
			targetURL: "/cas/login?service=" + url.QueryEscape("https://malicious.example.com/callback"),
			mockSetup: func() {
				s.casSvc.EXPECT().
					GenerateTicket(gomock.Any(), int64(100), int64(1), "alice", "https://malicious.example.com/callback").
					Return("", errs.ErrCasServiceNotRegistered)
			},
			wantCode: http.StatusForbidden,
			wantBody: "目标服务未在当前租户或系统级接入应用白名单中注册，拒绝跳转",
		},
		{
			name:      "服务内部异常返回 500",
			targetURL: "/cas/login?service=" + url.QueryEscape("https://jumpserver.example.com/callback"),
			mockSetup: func() {
				s.casSvc.EXPECT().
					GenerateTicket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return("", errors.New("redis connection error"))
			},
			wantCode: http.StatusInternalServerError,
			wantBody: "生成单点登录凭据失败",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			tc.mockSetup()

			req := httptest.NewRequest(http.MethodGet, tc.targetURL, nil)
			if tc.isAnonymous {
				req.Header.Set("X-Anonymous", "true")
			}
			w := httptest.NewRecorder()
			s.server.ServeHTTP(w, req)

			assert.Equal(s.T(), tc.wantCode, w.Code)
			if tc.wantLocation != "" {
				assert.Equal(s.T(), tc.wantLocation, w.Header().Get("Location"))
			}
			if tc.wantBody != "" {
				assert.Contains(s.T(), w.Body.String(), tc.wantBody)
			}
		})
	}
}

// --- 2. CasServiceValidate 端点测试 (GET /cas/serviceValidate & /cas/p3/serviceValidate) ---

func (s *CasHandlerTestSuite) TestCasServiceValidate() {
	sampleResult := &domain.CasValidationResult{
		User: domain.User{
			Username: "alice",
			Email:    "alice@example.com",
		},
		Attributes: map[string]any{
			"email": "alice@example.com",
		},
	}

	testCases := []struct {
		name        string
		endpoint    string
		accept      string
		mockSetup   func()
		wantCode    int
		wantBodySub string
	}{
		{
			name:     "缺少参数默认 XML 返回失败",
			endpoint: "/cas/serviceValidate",
			mockSetup: func() {
				s.casSvc.EXPECT().
					BuildFailureXML("INVALID_REQUEST", "缺少 ticket 或 service 参数").
					Return("<cas:authenticationFailure code=\"INVALID_REQUEST\">缺少 ticket 或 service 参数</cas:authenticationFailure>")
			},
			wantCode:    http.StatusOK,
			wantBodySub: "<cas:authenticationFailure code=\"INVALID_REQUEST\">",
		},
		{
			name:     "缺少参数且 format=json 返回 JSON 失败",
			endpoint: "/cas/serviceValidate?format=json",
			mockSetup: func() {
				s.casSvc.EXPECT().
					BuildFailureJSON("INVALID_REQUEST", "缺少 ticket 或 service 参数").
					Return(&domain.CasJsonResponse{
						ServiceResponse: domain.CasJsonServiceResponse{
							AuthenticationFailure: &domain.CasJsonFailure{
								Code:        "INVALID_REQUEST",
								Description: "缺少 ticket 或 service 参数",
							},
						},
					})
			},
			wantCode:    http.StatusOK,
			wantBodySub: `"code":"INVALID_REQUEST"`,
		},
		{
			name:     "票据核销失败默认 XML",
			endpoint: "/cas/serviceValidate?service=https://app.com&ticket=ST-expired",
			mockSetup: func() {
				s.casSvc.EXPECT().
					ValidateTicket(gomock.Any(), "ST-expired", "https://app.com").
					Return(nil, errs.ErrCasTicketInvalid)
				s.casSvc.EXPECT().
					BuildFailureXML("INVALID_TICKET", errs.ErrCasTicketInvalid.Error()).
					Return("<cas:authenticationFailure code=\"INVALID_TICKET\">票据无效或已过期</cas:authenticationFailure>")
			},
			wantCode:    http.StatusOK,
			wantBodySub: "票据无效或已过期",
		},
		{
			name:     "票据核销成功默认 XML (CAS 2.0/3.0)",
			endpoint: "/cas/serviceValidate?service=https://app.com&ticket=ST-valid",
			mockSetup: func() {
				s.casSvc.EXPECT().
					ValidateTicket(gomock.Any(), "ST-valid", "https://app.com").
					Return(sampleResult, nil)
				s.casSvc.EXPECT().
					BuildSuccessXML(sampleResult).
					Return("<cas:serviceResponse><cas:authenticationSuccess><cas:user>alice</cas:user></cas:authenticationSuccess></cas:serviceResponse>")
			},
			wantCode:    http.StatusOK,
			wantBodySub: "<cas:user>alice</cas:user>",
		},
		{
			name:     "CAS 3.0 p3 端点且 Accept 为 application/json 成功返回 JSON",
			endpoint: "/cas/p3/serviceValidate?service=https://app.com&ticket=ST-valid",
			accept:   "application/json",
			mockSetup: func() {
				s.casSvc.EXPECT().
					ValidateTicket(gomock.Any(), "ST-valid", "https://app.com").
					Return(sampleResult, nil)
				s.casSvc.EXPECT().
					BuildSuccessJSON(sampleResult).
					Return(&domain.CasJsonResponse{
						ServiceResponse: domain.CasJsonServiceResponse{
							AuthenticationSuccess: &domain.CasJsonSuccess{
								User: "alice",
								Attributes: map[string]any{
									"email": "alice@example.com",
								},
							},
						},
					})
			},
			wantCode:    http.StatusOK,
			wantBodySub: `"user":"alice"`,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			tc.mockSetup()

			req := httptest.NewRequest(http.MethodGet, tc.endpoint, nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			w := httptest.NewRecorder()
			s.server.ServeHTTP(w, req)

			assert.Equal(s.T(), tc.wantCode, w.Code)
			assert.Contains(s.T(), w.Body.String(), tc.wantBodySub)
		})
	}
}

// --- 3. CasValidate 端点测试 (GET /cas/validate - CAS 1.0 协议) ---

func (s *CasHandlerTestSuite) TestCasValidate() {
	testCases := []struct {
		name      string
		targetURL string
		mockSetup func()
		wantBody  string
	}{
		{
			name:      "缺少参数返回 no",
			targetURL: "/cas/validate",
			mockSetup: func() {},
			wantBody:  "no\n",
		},
		{
			name:      "票据无效返回 no",
			targetURL: "/cas/validate?service=https://app.com&ticket=ST-invalid",
			mockSetup: func() {
				s.casSvc.EXPECT().
					ValidatePlainText(gomock.Any(), "ST-invalid", "https://app.com").
					Return(false, "")
			},
			wantBody: "no\n",
		},
		{
			name:      "票据有效返回 yes\\nalice\\n",
			targetURL: "/cas/validate?service=https://app.com&ticket=ST-valid",
			mockSetup: func() {
				s.casSvc.EXPECT().
					ValidatePlainText(gomock.Any(), "ST-valid", "https://app.com").
					Return(true, "alice")
			},
			wantBody: "yes\nalice\n",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			tc.mockSetup()

			req := httptest.NewRequest(http.MethodGet, tc.targetURL, nil)
			w := httptest.NewRecorder()
			s.server.ServeHTTP(w, req)

			assert.Equal(s.T(), http.StatusOK, w.Code)
			assert.Equal(s.T(), "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
			assert.Equal(s.T(), tc.wantBody, w.Body.String())
		})
	}
}

// --- 4. CasLogout 端点测试 (GET /cas/logout) ---

func (s *CasHandlerTestSuite) TestCasLogout() {
	s.Run("提供目标 service 重定向回目标", func() {
		req := httptest.NewRequest(http.MethodGet, "/cas/logout?service="+url.QueryEscape("https://app.com/bye"), nil)
		w := httptest.NewRecorder()
		s.server.ServeHTTP(w, req)

		assert.Equal(s.T(), http.StatusFound, w.Code)
		assert.Equal(s.T(), "https://app.com/bye", w.Header().Get("Location"))
	})

	s.Run("提供 url 参数重定向回目标", func() {
		req := httptest.NewRequest(http.MethodGet, "/cas/logout?url="+url.QueryEscape("https://app.com/bye2"), nil)
		w := httptest.NewRecorder()
		s.server.ServeHTTP(w, req)

		assert.Equal(s.T(), http.StatusFound, w.Code)
		assert.Equal(s.T(), "https://app.com/bye2", w.Header().Get("Location"))
	})

	s.Run("未提供目标重定向回系统登录页", func() {
		req := httptest.NewRequest(http.MethodGet, "/cas/logout", nil)
		w := httptest.NewRecorder()
		s.server.ServeHTTP(w, req)

		assert.Equal(s.T(), http.StatusFound, w.Code)
		assert.Equal(s.T(), "/login", w.Header().Get("Location"))
	})
}

// --- 5. appendTicketToURL 基础工具函数测试 ---

func (s *CasHandlerTestSuite) TestAppendTicketToURL() {
	testCases := []struct {
		name      string
		targetURL string
		ticket    string
		wantURL   string
	}{
		{
			name:      "纯地址注入 ticket",
			targetURL: "https://example.com/callback",
			ticket:    "ST-123456",
			wantURL:   "https://example.com/callback?ticket=ST-123456",
		},
		{
			name:      "已存在 query 参数拼接",
			targetURL: "https://example.com/callback?redirect=/home",
			ticket:    "ST-123456",
			wantURL:   "https://example.com/callback?redirect=%2Fhome&ticket=ST-123456",
		},
		{
			name:      "包含 Fragment 锚点时 query 注入在 Fragment 之前",
			targetURL: "https://example.com/app#dashboard",
			ticket:    "ST-123456",
			wantURL:   "https://example.com/app?ticket=ST-123456#dashboard",
		},
		{
			name:      "既有 query 又有 Fragment",
			targetURL: "https://example.com/app?foo=bar#dashboard",
			ticket:    "ST-123456",
			wantURL:   "https://example.com/app?foo=bar&ticket=ST-123456#dashboard",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			got := appendTicketToURL(tc.targetURL, tc.ticket)
			assert.Equal(s.T(), tc.wantURL, got)
		})
	}
}

func TestCasHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(CasHandlerTestSuite))
}
