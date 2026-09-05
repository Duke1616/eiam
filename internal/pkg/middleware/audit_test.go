package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	auditevt "github.com/Duke1616/eiam/internal/event/audit"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRecorder struct {
	mu      sync.Mutex
	records []domain.OperationLog
}

func (m *mockRecorder) Record(log domain.OperationLog) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, log)
}

func (m *mockRecorder) Records() []domain.OperationLog {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]domain.OperationLog, len(m.records))
	copy(copied, m.records)
	return copied
}

type mockProducer struct{}

func (m *mockProducer) Produce(ctx context.Context, evt auditevt.Event) error {
	return nil
}
func (m *mockProducer) RecordOperation(ctx context.Context, log domain.OperationLog) error {
	return nil
}
func (m *mockProducer) RecordAuth(ctx context.Context, log domain.AuthLog) error {
	return nil
}

func TestAuditMatcher_TableDriven(t *testing.T) {
	cfg := DefaultAuditConfig()
	matcher := NewAuditMatcher(cfg)

	testCases := []struct {
		name         string
		method       string
		path         string
		action       string
		shouldMethod bool
		ignoredPath  bool
		ignoredAct   bool
	}{
		{
			name:         "GET读请求默认不审计",
			method:       http.MethodGet,
			path:         "/api/user/profile",
			action:       "iam:user:profile",
			shouldMethod: false,
			ignoredPath:  false,
			ignoredAct:   false,
		},
		{
			name:         "普通写接口默认应当被审计",
			method:       http.MethodPost,
			path:         "/api/role/create",
			action:       "iam:role:add",
			shouldMethod: true,
			ignoredPath:  false,
			ignoredAct:   false,
		},
		{
			name:         "系统免审前缀接口",
			method:       http.MethodPost,
			path:         "/api/permission/sync",
			action:       "iam:permission:sync",
			shouldMethod: true,
			ignoredPath:  true,
			ignoredAct:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.shouldMethod, matcher.ShouldAuditMethod(tc.method))
			assert.Equal(t, tc.ignoredPath, matcher.IsIgnoredPath(tc.path))
			assert.Equal(t, tc.ignoredAct, matcher.IsIgnoredAction(tc.action))
		})
	}
}

func TestAuditMiddleware_Exclusion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reg := capability.NewRegistry("iam", "test", "测试模块")
	rec := &mockRecorder{}
	matcher := NewAuditMatcher(DefaultAuditConfig())

	builder := NewAuditBuilder(&mockProducer{}, matcher).WithRecorder(rec)

	engine := gin.New()
	engine.Use(builder.Build())

	// 1. 普通需审计写接口 (未声明 NoAudit，应正常记录)
	engine.POST("/api/test/create", reg.Define("创建资源", "create").
		Bind(func(c *gin.Context) {
			c.Status(http.StatusOK)
		}),
	)

	// 2. 核心验证：租户切换接口仅通过代码级 NoAudit() 声明免审，无需任何 config 配置
	engine.POST("/api/tenant/switch", reg.Define("切换租户空间", "switch").
		NoAudit().
		Bind(func(c *gin.Context) {
			c.Status(http.StatusOK)
		}),
	)

	// 3. 自定义业务通过 Route(WithNoAudit()) 显式免审
	engine.POST("/api/custom/ping", reg.Define("内部心跳", "ping").
		Route(capability.WithNoAudit()).
		Handle(func(c *gin.Context) {
			c.Status(http.StatusOK)
		}),
	)

	// 4. 退出登录接口免操作审计
	engine.POST("/api/user/logout", reg.Define("退出登录", "logout").
		NoAudit().
		Bind(func(c *gin.Context) {
			c.Status(http.StatusOK)
		}),
	)

	testCases := []struct {
		name          string
		method        string
		path          string
		expectAudited bool
	}{
		{
			name:          "普通写接口正常记录审计",
			method:        http.MethodPost,
			path:          "/api/test/create",
			expectAudited: true,
		},
		{
			name:          "租户切换通过代码级 NoAudit 声明彻底免审",
			method:        http.MethodPost,
			path:          "/api/tenant/switch",
			expectAudited: false,
		},
		{
			name:          "Route(WithNoAudit) 修饰接口彻底免审",
			method:        http.MethodPost,
			path:          "/api/custom/ping",
			expectAudited: false,
		},
		{
			name:          "退出登录接口彻底免除操作审计",
			method:        http.MethodPost,
			path:          "/api/user/logout",
			expectAudited: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			beforeCount := len(rec.Records())

			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			afterCount := len(rec.Records())

			if tc.expectAudited {
				assert.Equal(t, beforeCount+1, afterCount, "普通业务写操作应产生1条操作审计日志")
			} else {
				assert.Equal(t, beforeCount, afterCount, "代码声明 NoAudit 的接口严禁产生操作审计日志")
			}
		})
	}
}
