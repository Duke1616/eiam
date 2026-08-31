package swagger

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSwaggerGenFullPipeline(t *testing.T) {
	tempDir := t.TempDir()
	handlerCode := `package demo

import "github.com/gin-gonic/gin"

type TestReq struct {
	// 用户登录名称
	Name string ` + "`" + `json:"name" binding:"required"` + "`" + `
	Code string ` + "`" + `json:"code"` + "`" + `
}

func (h *Handler) Routes(server *gin.Engine) {
	g := server.Group("/api/demo")
	g.POST("/test", h.Define("测试端点", "test").Bind(ginx.B[TestReq](h.Test)))
	g.GET("/info", h.Define("查看信息", "info").Bind(ginx.W(h.Info)))
	g.DELETE("/delete/:id", h.Define("删除项目", "delete").Bind(ginx.W(h.Delete)))
}
`
	srcFile := filepath.Join(tempDir, "handler.go")
	require.NoError(t, os.WriteFile(srcFile, []byte(handlerCode), 0644))

	parser := NewParser()
	endpoints, structs, err := parser.ParseDir(tempDir)
	require.NoError(t, err)
	require.Len(t, endpoints, 3)
	require.Contains(t, structs, "TestReq")

	assert.Equal(t, "POST", endpoints[0].Method)
	assert.Equal(t, "/api/demo/test", endpoints[0].Path)
	assert.Equal(t, "测试端点", endpoints[0].Summary)
	assert.Equal(t, "TestReq", endpoints[0].ReqType)

	assert.Equal(t, "GET", endpoints[1].Method)
	assert.Equal(t, "/api/demo/info", endpoints[1].Path)
	assert.Equal(t, "查看信息", endpoints[1].Summary)

	assert.Equal(t, "DELETE", endpoints[2].Method)
	assert.Equal(t, "/api/demo/delete/:id", endpoints[2].Path)

	// 生成测试
	jsonPath := filepath.Join(tempDir, "swagger.json")
	htmlPath := filepath.Join(tempDir, "index.html")

	gen := NewGenerator("Demo API", "1.0.0")
	require.NoError(t, gen.Generate(endpoints, structs, jsonPath, htmlPath))

	jsonBytes, err := os.ReadFile(jsonPath)
	require.NoError(t, err)
	assert.Contains(t, string(jsonBytes), "/api/demo/test")
	assert.Contains(t, string(jsonBytes), "TestReq")
	assert.Contains(t, string(jsonBytes), `"example"`)
	assert.Contains(t, string(jsonBytes), `"name": "示例名称"`)
	assert.Contains(t, string(jsonBytes), "用户登录名称")

	// 验证路径参数转换与 parameters 定义
	assert.Contains(t, string(jsonBytes), "/api/demo/delete/{id}")
	assert.Contains(t, string(jsonBytes), `"in": "path"`)
	assert.Contains(t, string(jsonBytes), `"name": "id"`)

	// 验证 Bearer Token 安全模式
	assert.Contains(t, string(jsonBytes), "BearerAuth")
	assert.Contains(t, string(jsonBytes), "securitySchemes")

	htmlBytes, err := os.ReadFile(htmlPath)
	require.NoError(t, err)
	assert.Contains(t, string(htmlBytes), "Demo API")
	assert.Contains(t, string(htmlBytes), "@scalar/api-reference")
}
