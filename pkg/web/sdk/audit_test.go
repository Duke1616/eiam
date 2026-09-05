package sdk

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func dummyHostCreateHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": 1001, "status": "created"})
}

func TestCheckPolicy_TransparentAuditEnforcement(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var (
		mu           sync.Mutex
		batchRecords []OperationRecord
	)

	// 1. 模拟 EIAM 服务端端点 (/api/permission/check_policy 和 /api/audit/batch)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/permission/check_policy":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(apiResult[authorizeResult]{
				Code: 0,
				Data: authorizeResult{
					Decision: pbac.Decision{
						Allowed: true,
					},
					Audit: true,
				},
			})
		case "/api/audit/batch":
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Records []OperationRecord `json:"records"`
			}
			_ = json.Unmarshal(body, &req)

			mu.Lock()
			batchRecords = append(batchRecords, req.Records...)
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(apiResult[any]{Code: 0, Msg: "ok"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// 2. 模拟微服务注册 capability 资产
	ptr := reflect.ValueOf(dummyHostCreateHandler).Pointer()
	capability.DefaultRuntime().Register(ptr, capability.ResourceInfo{
		Service: "ecmdb",
		Group:   "host",
		Code:    "CREATE_HOST",
		Name:    "新建CMDB主机",
	})

	// 3. 微服务无感初始化 SDK 并挂载 CheckPolicy
	sdk := NewSDKWithURL(server.URL)
	defer sdk.Close()

	r := gin.New()
	// 注入模拟登录上下文
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(ctxutil.WithUserAndTenant(c.Request.Context(), 666, 888))
		c.Next()
	})
	r.Use(sdk.CheckPolicy())

	r.POST("/api/v1/host/create", dummyHostCreateHandler)

	// 4. 客户端发起写请求
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/create?env=prod", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// 5. 等待后台 Batcher 批量聚合刷新
	time.Sleep(100 * time.Millisecond)
	sdk.Close() // 强制 flush

	mu.Lock()
	defer mu.Unlock()

	// 6. 核心断言：验证写操作被强制、透明、无感地上报给 EIAM 服务端
	assert.Equal(t, 1, len(batchRecords))
	record := batchRecords[0]
	assert.Equal(t, int64(888), record.TenantID)
	assert.Equal(t, int64(666), record.OperatorID)
	assert.Equal(t, "host", record.Module)
	assert.Equal(t, "CREATE_HOST", record.Action)
	assert.Equal(t, "新建CMDB主机", record.ResourceName)
	assert.Equal(t, "urn:iam:api:ecmdb:post:/api/v1/host/create", record.ResourceURN)
	assert.Equal(t, "SUCCESS", record.Status)
	assert.Equal(t, "env=prod", record.AfterState)
	assert.Greater(t, record.Ctime, int64(0))
}
