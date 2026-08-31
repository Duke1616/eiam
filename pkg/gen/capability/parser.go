package capability

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// Parser 基于 Go AST 的权限静态分析流水线
type Parser struct {
	fset *token.FileSet
}

// NewParser 创建 AST 分析器实例
func NewParser() *Parser {
	return &Parser{fset: token.NewFileSet()}
}

// ParseDir 递归扫描目录，抽取所有路由与权限特征并构建拓扑图
func (p *Parser) ParseDir(dir string) (*Graph, error) {
	graph := NewGraph()
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		graph.ProjectName = strings.ToUpper(filepath.Base(cwd))
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fileNode, err := parser.ParseFile(p.fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}

		p.parseFile(fileNode, path, graph)
		return nil
	})

	return graph, err
}

type fileMetadata struct {
	service      string
	module       string
	title        string
	defaultScope Scope
	subModules   map[string]string // 局部变量 -> 子模块名
}

// parseFile 分析单个文件，抽取 Registry 与能力定义
func (p *Parser) parseFile(file *ast.File, filePath string, graph *Graph) {
	// 从文件头部原生 AST Imports 中自动识别 capability SDK 依赖路径
	if graph.CapabilityPkg == "" {
		for _, imp := range file.Imports {
			if imp.Path != nil {
				pkgPath := strings.Trim(imp.Path.Value, `"`)
				if strings.HasSuffix(pkgPath, "/capability") {
					graph.CapabilityPkg = pkgPath
					break
				}
			}
		}
	}

	meta := p.extractMetadata(file)
	if meta.service == "" || meta.module == "" {
		return
	}

	modID := meta.service + ":" + meta.module
	if mod, ok := graph.Modules[modID]; ok {
		if mod.Title == "" {
			mod.Title = meta.title
		}
		if mod.DefaultScope == "" {
			mod.DefaultScope = meta.defaultScope
		}
	} else {
		graph.Modules[modID] = &Module{
			Service:      meta.service,
			Name:         meta.module,
			Title:        meta.title,
			DefaultScope: meta.defaultScope,
			File:         filePath,
		}
	}

	p.extractActions(file, filePath, meta, graph)
}

// extractMetadata 提取当前文件的基础服务、模块、作用域及子模块声明
func (p *Parser) extractMetadata(file *ast.File) fileMetadata {
	meta := fileMetadata{
		defaultScope: ScopeTenant,
		subModules:   make(map[string]string),
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			chain := UnwindCallChain(node)
			if step := chain.Find("NewRegistry"); step != nil && len(step.Args) >= 2 {
				meta.service = ExtractString(step.Args[0])
				meta.module = ExtractString(step.Args[1])
				if len(step.Args) >= 3 {
					meta.title = ExtractString(step.Args[2])
				}
			}
			if step := chain.Find("DefaultScope"); step != nil && len(step.Args) > 0 {
				meta.defaultScope = ExtractScope(step.Args[0])
			}

		case *ast.AssignStmt:
			if len(node.Lhs) == 1 && len(node.Rhs) == 1 {
				if ident, ok := node.Lhs[0].(*ast.Ident); ok {
					if call, ok := node.Rhs[0].(*ast.CallExpr); ok {
						chain := UnwindCallChain(call)
						if step := chain.Find("Sub", "Module"); step != nil && len(step.Args) >= 1 {
							meta.subModules[ident.Name] = ExtractString(step.Args[0])
						}
					}
				}
			}
		}
		return true
	})

	return meta
}

// extractActions 分析能力定义调用链，构建受控权限点
func (p *Parser) extractActions(file *ast.File, filePath string, meta fileMetadata, graph *Graph) {
	seenLines := make(map[int]bool)

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		chain := UnwindCallChain(call)
		defineStep := chain.Find("Define", "Capability")
		if defineStep == nil || len(defineStep.Args) < 2 {
			return true
		}

		line := p.fset.Position(defineStep.Pos).Line
		if seenLines[line] {
			return true
		}
		seenLines[line] = true

		targetModule := meta.module
		targetSubMod := meta.subModules[defineStep.Receiver]

		if target := chain.ExtractTargetModel(); target != "" {
			targetModule = target
			targetSubMod = ""
		} else if strings.HasSuffix(defineStep.Receiver, "Module") && len(defineStep.Receiver) > 6 {
			targetModule = ToSnakeCase(strings.TrimSuffix(defineStep.Receiver, "Module"))
			targetSubMod = ""
		}

		act := &Action{
			Service:      meta.service,
			Module:       targetModule,
			SubModule:    targetSubMod,
			OriginModule: meta.module,
			Name:         ExtractString(defineStep.Args[0]),
			Action:       ExtractString(defineStep.Args[1]),
			Scope:        meta.defaultScope,
			File:         filePath,
			Line:         line,
		}

		for _, step := range chain {
			switch step.Method {
			case "Needs":
				for _, arg := range step.Args {
					if s := ExtractString(arg); s != "" {
						if !strings.Contains(s, ":") {
							// 短码自动补齐当前模块前缀 (如 "get" -> "iam:user:get")
							s = fmt.Sprintf("%s:%s:%s", meta.service, targetModule, s)
						}
						act.Needs = append(act.Needs, s)
					} else if ref := ExtractPermRef(meta.service, arg); ref != "" {
						// 强类型引用 (如 perm.User.Get)
						act.Needs = append(act.Needs, ref)
					}
				}
			case "NoSync":
				act.NoSync = true
			case "Scope":
				if len(step.Args) > 0 {
					act.Scope = ExtractScope(step.Args[0])
				}
			}
		}

		graph.AddAction(act)
		return true
	})
}
