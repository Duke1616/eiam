package capability

import (
	goParser "go/parser"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermGenFullPipeline(t *testing.T) {
	tempDir := t.TempDir()
	sourceFile := filepath.Join(tempDir, "handler.go")

	code := `package mock

import (
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	capability.IRegistry
}

func NewHandler() *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "demo", "示例服务"),
	}
}

func (h *Handler) Routes(server *gin.Engine) {
	g := server.Group("/api/demo")
	g.POST("/list", h.Define("用户列表", "view"))
	g.GET("/detail", h.Define("用户详情", "get"))
	g.POST("/update", h.Define("修改用户", "edit").Needs("iam:demo:get"))

	sub := h.Module("child", "子领域")
	g.POST("/child/sync", sub.Define("数据同步", "sync"))
}
`
	require.NoError(t, os.WriteFile(sourceFile, []byte(code), 0644))

	// 1. 测试 AST 解析
	parser := NewParser()
	graph, err := parser.ParseDir(tempDir)
	require.NoError(t, err)

	mod, exists := graph.Modules["iam:demo"]
	require.True(t, exists)
	assert.Equal(t, "示例服务", mod.Title)
	assert.Len(t, mod.Actions, 4)

	assert.Contains(t, graph.Actions, "iam:demo:view")
	assert.Contains(t, graph.Actions, "iam:demo:get")
	assert.Contains(t, graph.Actions, "iam:demo:edit")
	assert.Contains(t, graph.Actions, "iam:demo.child:sync")

	editAct := graph.Actions["iam:demo:edit"]
	require.NotNil(t, editAct)
	assert.Equal(t, []string{"iam:demo:get"}, editAct.Needs)

	// 2. 测试合法拓扑校验
	validator := NewValidator()
	issues := validator.Validate(graph)
	assert.Empty(t, issues)

	// 3. 测试 Go 契约与 Markdown 渲染
	emitter := NewEmitter()
	goPath := filepath.Join(tempDir, "out", "perms.go")
	docPath := filepath.Join(tempDir, "out", "perms.md")

	require.NoError(t, emitter.EmitGoContract(graph, goPath))
	require.NoError(t, emitter.EmitMarkdownReport(graph, docPath, "测试权限大盘"))

	goBytes, err := os.ReadFile(goPath)
	require.NoError(t, err)
	assert.Contains(t, string(goBytes), "var Demo = struct")
	assert.Contains(t, string(goBytes), "iam:demo:edit")
	assert.Contains(t, string(goBytes), "iam:demo.child:sync")

	docBytes, err := os.ReadFile(docPath)
	require.NoError(t, err)
	assert.Contains(t, string(docBytes), "示例服务")
	assert.Contains(t, string(docBytes), "`iam:demo:get`")
}

func TestValidatorDanglingAndCycle(t *testing.T) {
	g := NewGraph()
	g.AddAction(&Action{
		Service: "iam",
		Module:  "sample",
		Action:  "edit",
		Needs:   []string{"iam:sample:get_typo"},
		File:    "sample.go",
		Line:    20,
	})
	g.AddAction(&Action{
		Service: "iam",
		Module:  "sample",
		Action:  "get",
		File:    "sample.go",
		Line:    25,
	})

	validator := NewValidator()
	issues := validator.Validate(g)
	require.Len(t, issues, 1)
	assert.Equal(t, "ERROR", issues[0].Severity)
	assert.Contains(t, issues[0].Message, "未找到")
	assert.Contains(t, issues[0].Suggestion, "iam:sample:get")

	// 注入循环依赖
	g.AddAction(&Action{
		Service: "iam",
		Module:  "sample",
		Action:  "loop_a",
		Needs:   []string{"iam:sample:loop_b"},
	})
	g.AddAction(&Action{
		Service: "iam",
		Module:  "sample",
		Action:  "loop_b",
		Needs:   []string{"iam:sample:loop_a"},
	})

	cycleIssues := validator.checkCycles(g)
	require.NotEmpty(t, cycleIssues)
	assert.Contains(t, cycleIssues[0].Message, "循环依赖闭环")
}

func TestExtractPermRef(t *testing.T) {
	testCases := []struct {
		name       string
		curService string
		exprCode   string
		want       string
	}{
		{
			name:       "跨服务 etaskperm.Runner.Ids -> task:runner:ids",
			curService: "iam",
			exprCode:   "etaskperm.Runner.Ids",
			want:       "task:runner:ids",
		},
		{
			name:       "跨服务原生 taskperm.Runner.Ids -> task:runner:ids",
			curService: "iam",
			exprCode:   "taskperm.Runner.Ids",
			want:       "task:runner:ids",
		},
		{
			name:       "跨服务 eflow 别名 eflowperm.Ticket.Approve -> ticket:ticket:approve",
			curService: "iam",
			exprCode:   "eflowperm.Ticket.Approve",
			want:       "ticket:ticket:approve",
		},
		{
			name:       "跨服务 ecmdbperm.Host.List -> cmdb:host:list",
			curService: "iam",
			exprCode:   "ecmdbperm.Host.List",
			want:       "cmdb:host:list",
		},
		{
			name:       "本服务内部引用 permission.User.Get -> iam:user:get",
			curService: "iam",
			exprCode:   "permission.User.Get",
			want:       "iam:user:get",
		},
		{
			name:       "前缀假阳性防误伤 (不以规范后缀结尾不识别为微服务)",
			curService: "iam",
			exprCode:   "taskbar.User.Get",
			want:       "iam:user:get",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expr, err := goParser.ParseExpr(tc.exprCode)
			require.NoError(t, err)
			assert.Equal(t, tc.want, ExtractPermRef(tc.curService, expr))
		})
	}
}

