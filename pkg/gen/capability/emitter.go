package capability

import (
	"bytes"
	_ "embed"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

var (
	//go:embed templates/perm.go.tmpl
	permTmpl string

	//go:embed templates/model.go.tmpl
	modelTmpl string

	//go:embed templates/permissions.md.tmpl
	docTmpl string
)

// Emitter 负责将 Graph 拓扑模型渲染为 Go 契约与 Markdown 字典
type Emitter struct{}

// NewEmitter 创建渲染器实例
func NewEmitter() *Emitter {
	return &Emitter{}
}

// EmitGoContract 生成强类型 Go 权限契约包 (pkg/contract/perm/zz_generated_perms.go)
func (e *Emitter) EmitGoContract(g *Graph, outPath string) error {
	return renderAndWriteGo(permTmpl, map[string]any{"Modules": g.SortedModules()}, outPath)
}

// EmitContractModels 生成业务领域模型元数据 (pkg/contract/model/zz_generated_models.go)
func (e *Emitter) EmitContractModels(g *Graph, outPath string, capabilityPkg string) error {
	if capabilityPkg == "" {
		capabilityPkg = "github.com/Duke1616/eiam/pkg/web/capability"
	}
	data := map[string]any{
		"Modules":       g.SortedModules(),
		"CapabilityPkg": capabilityPkg,
	}
	return renderAndWriteGo(modelTmpl, data, outPath)
}

// EmitMarkdownReport 生成权限拓扑大盘可视化文档 (docs/permissions.md)
func (e *Emitter) EmitMarkdownReport(g *Graph, outPath string, title string) error {
	t, err := template.New("doc").Funcs(template.FuncMap{
		"join": strings.Join,
		"formatNeed": func(code string) string {
			if act, ok := g.Actions[code]; ok && act.Name != "" {
				return fmt.Sprintf("%s · `%s`", act.Name, code)
			}
			return fmt.Sprintf("`%s`", code)
		},
	}).Parse(docTmpl)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	data := map[string]any{
		"Title":        title,
		"Modules":      g.SortedModules(),
		"TotalActions": len(g.Actions),
	}
	if err = t.Execute(&buf, data); err != nil {
		return err
	}

	if err = os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(outPath, buf.Bytes(), 0644)
}

func renderAndWriteGo(tmplText string, data any, outPath string) error {
	t, err := template.New("tmpl").Parse(tmplText)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err = t.Execute(&buf, data); err != nil {
		return err
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return fmt.Errorf("格式化 Go 代码失败: %w\n%s", err, buf.String())
	}

	if err = os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}

	return os.WriteFile(outPath, formatted, 0644)
}
