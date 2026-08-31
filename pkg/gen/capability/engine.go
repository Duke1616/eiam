package capability

import (
	"context"
	"fmt"
	"os"
)

// Config 声明权限生成引擎的运行参数
type Config struct {
	ScanDir    string // AST 扫描的根目录，如 "./internal/web"
	GoOut      string // Go 强类型契约输出路径，如 "./pkg/contract/permission/zz_generated_perms.go"
	ModelOut   string // 业务领域模型输出路径，如 "./pkg/contract/model/zz_generated_models.go"
	DocOut     string // 权限大盘文档输出路径，如 "./docs/permissions.md"
	StrictMode bool   // 严格模式 (存在校验错误时是否中断)
}

// Engine 权限生成流水线统一执行引擎 (Facade)
type Engine struct {
	cfg       Config
	parser    *Parser
	validator *Validator
	emitter   *Emitter
}

// NewEngine 创建生成引擎实例
func NewEngine(cfg Config) *Engine {
	return &Engine{
		cfg:       cfg,
		parser:    NewParser(),
		validator: NewValidator(),
		emitter:   NewEmitter(),
	}
}

// Run 执行全套流水线：AST 扫描 -> 拓扑诊断 -> 契约代码生成 -> 字典文档渲染
func (e *Engine) Run(ctx context.Context) error {
	graph, err := e.parser.ParseDir(e.cfg.ScanDir)
	if err != nil {
		return fmt.Errorf("源码 AST 分析失败: %w", err)
	}

	projectInfo := ""
	if graph.ProjectName != "" {
		projectInfo = fmt.Sprintf(" (工程: %s)", graph.ProjectName)
	}
	fmt.Printf("[permgen] 正在扫描 AST 提取权限定义%s...\n", projectInfo)
	fmt.Printf("[permgen] 解析完成: 共 %d 个业务模块，%d 个受控权限点\n", len(graph.Modules), len(graph.Actions))

	// 拓扑健康检查
	issues := e.validator.Validate(graph)
	hasError := e.reportIssues(issues)

	if hasError && e.cfg.StrictMode {
		return fmt.Errorf("严格模式检测到权限拓扑错误，已阻断生成")
	}

	// 导出契约与文档
	if e.cfg.GoOut != "" {
		if err = e.emitter.EmitGoContract(graph, e.cfg.GoOut); err != nil {
			return fmt.Errorf("生成 Go 权限契约失败: %w", err)
		}
		fmt.Printf("[permgen] 生成 Go 权限契约: %s\n", e.cfg.GoOut)
	}

	if e.cfg.ModelOut != "" {
		if err = e.emitter.EmitContractModels(graph, e.cfg.ModelOut, graph.CapabilityPkg); err != nil {
			return fmt.Errorf("生成业务领域模型失败: %w", err)
		}
		fmt.Printf("[permgen] 生成领域模型元数据: %s\n", e.cfg.ModelOut)
	}

	if e.cfg.DocOut != "" {
		if err = e.emitter.EmitMarkdownReport(graph, e.cfg.DocOut, graph.DocTitle()); err != nil {
			return fmt.Errorf("生成权限大盘字典失败: %w", err)
		}
		fmt.Printf("[permgen] 生成权限大盘字典: %s\n", e.cfg.DocOut)
	}

	fmt.Println("[permgen] 执行完毕")
	return nil
}

func (e *Engine) reportIssues(issues []Issue) bool {
	if len(issues) == 0 {
		fmt.Println("[permgen] 拓扑校验通过，未发现悬空或循环依赖")
		return false
	}

	fmt.Println("\n[permgen] 拓扑健康诊断报告:")
	hasError := false
	for _, issue := range issues {
		if issue.Severity == "ERROR" {
			hasError = true
			fmt.Printf("  [error] %s:%d\n    %s\n", issue.File, issue.Line, issue.Message)
			if issue.Suggestion != "" {
				fmt.Printf("    hint: %s\n", issue.Suggestion)
			}
		} else {
			fmt.Printf("  [warn] %s:%d\n    %s\n", issue.File, issue.Line, issue.Message)
		}
	}
	fmt.Fprintln(os.Stdout)
	return hasError
}
