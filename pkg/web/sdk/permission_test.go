package sdk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePolicyPath(t *testing.T) {
	testCases := []struct {
		name     string
		prefix   string
		input    string
		expected string
	}{
		{
			name:     "带有正常前缀与子路径",
			prefix:   "/api/plugin-runtime/builtin.ssh",
			input:    "/sftp/delete",
			expected: "/api/plugin-runtime/builtin.ssh/sftp/delete",
		},
		{
			name:     "带有前缀且访问根路径",
			prefix:   "/api/plugin-runtime/builtin.ssh",
			input:    "/",
			expected: "/api/plugin-runtime/builtin.ssh",
		},
		{
			name:     "无前缀正常访问",
			prefix:   "",
			input:    "/sftp/delete",
			expected: "/sftp/delete",
		},
		{
			name:     "前缀带有首尾多余斜杠格式化",
			prefix:   "//custom/prefix///",
			input:    "users/list",
			expected: "/custom/prefix/users/list",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSDKWithURL("http://127.0.0.1:9000", WithTimeout(2*time.Second)).WithPathPrefix(tc.prefix)
			assert.Equal(t, tc.expected, s.resolvePolicyPath(tc.input))
		})
	}
}

func TestCheckPolicyInjectsVerifiedDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)

	decision := pbac.Decision{
		Allowed:       true,
		FilterProfile: "rows",
		AllowAccessScope: &pbac.AccessScope{Predicate: &pbac.Predicate{
			Key:      "row:owner",
			Operator: pbac.StringEquals,
			Values:   []pbac.Operand{pbac.Literal("alice")},
		}},
	}
	authorizationServer := newAuthorizationServer(t, decision)
	defer authorizationServer.Close()

	var received pbac.Decision
	registry := capability.NewRegistry("sdk-test", "row", "SDK test")
	handler := registry.Capability("List rows", "list").
		AccessScope("rows").
		Handle(func(ctx *gin.Context) {
			received, _ = pbac.DecisionFromContext(ctx.Request.Context())
			ctx.Status(http.StatusNoContent)
		})

	engine := gin.New()
	engine.Use(NewSDKWithURL(authorizationServer.URL).CheckPolicy())
	engine.GET("/rows", handler)

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rows", nil))

	assert.Equal(t, http.StatusNoContent, response.Code)
	assert.True(t, received.Allowed)
	assert.Equal(t, pbac.FilterProfile("rows"), received.FilterProfile)
	assert.NotNil(t, received.AllowAccessScope)
}

func TestCheckPolicyRejections(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name             string
		decision         pbac.Decision
		handlerProfile   pbac.FilterProfile
		expectedCode     int
		expectedBizCode  int
		expectedMsgMatch string
	}{
		{
			name: "显式拒绝返回 403001 及明确原因",
			decision: pbac.Decision{
				Allowed: false,
				Reason:  "用户缺少操作权限",
			},
			handlerProfile:   "rows",
			expectedCode:     http.StatusForbidden,
			expectedBizCode:  403001,
			expectedMsgMatch: "用户缺少操作权限",
		},
		{
			name: "数据范围画像不匹配返回 403002",
			decision: pbac.Decision{
				Allowed:       true,
				FilterProfile: "other_rows",
			},
			handlerProfile:   "rows",
			expectedCode:     http.StatusForbidden,
			expectedBizCode:  403002,
			expectedMsgMatch: "数据范围约束配置不匹配",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authorizationServer := newAuthorizationServer(t, tc.decision)
			defer authorizationServer.Close()

			called := false
			registry := capability.NewRegistry("sdk-test", "row", "SDK test")
			handler := registry.Capability("List rows", "list").
				AccessScope(tc.handlerProfile).
				Handle(func(ctx *gin.Context) {
					called = true
					ctx.Status(http.StatusNoContent)
				})

			engine := gin.New()
			engine.Use(NewSDKWithURL(authorizationServer.URL).CheckPolicy())
			engine.GET("/rows", handler)

			response := httptest.NewRecorder()
			engine.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rows", nil))

			assert.Equal(t, tc.expectedCode, response.Code)
			assert.False(t, called, "被拒绝后业务 Handler 绝对不能被执行")

			var res ginx.Result
			err := json.Unmarshal(response.Body.Bytes(), &res)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedBizCode, res.Code)
			assert.Equal(t, tc.expectedMsgMatch, res.Msg)
		})
	}
}

func TestStandardHeadersForwarded(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var receivedHeaders http.Header
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apiResult[pbac.Decision]{
			Data: pbac.Decision{Allowed: true},
		})
	}))
	defer authServer.Close()

	registry := capability.NewRegistry("sdk-test", "row", "SDK test")
	handler := registry.Capability("List rows", "list").
		Handle(func(ctx *gin.Context) {
			ctx.Status(http.StatusOK)
		})

	engine := gin.New()
	engine.Use(NewSDKWithURL(authServer.URL).CheckPolicy())
	engine.GET("/rows", handler)

	req := httptest.NewRequest(http.MethodGet, "/rows", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Cookie", "session=test-cookie")
	req.Header.Set("X-Request-Id", "req-123456")
	req.Header.Set("X-Malicious-Header", "injected-value")

	resp := httptest.NewRecorder()
	engine.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "Bearer test-token", receivedHeaders.Get("Authorization"))
	assert.Equal(t, "session=test-cookie", receivedHeaders.Get("Cookie"))
	assert.Equal(t, "req-123456", receivedHeaders.Get("X-Request-Id"))
	assert.Empty(t, receivedHeaders.Get("X-Malicious-Header"), "未授权的自定义请求头绝对不允许透传")
}

func newAuthorizationServer(t *testing.T, decision pbac.Decision) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/permission/check_policy" {
			t.Errorf("unexpected authorization path: %s", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(apiResult[pbac.Decision]{Data: decision}); err != nil {
			t.Errorf("encode authorization response: %v", err)
		}
	}))
}
