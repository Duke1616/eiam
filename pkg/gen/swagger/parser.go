package swagger

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

var validHTTPMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

// Endpoint 记录 AST 静态提取出的单一 HTTP 端点契约
type Endpoint struct {
	Method      string // HTTP 方法 (GET, POST 等)
	Path        string // 完整 URL 路径 (/api/role/create)
	Summary     string // 接口业务摘要 (创建角色)
	Tag         string // 分组标签 (角色管理)
	ReqType     string // 入参结构体类型名 (CreateRoleRequest)
	Description string // 权限标识或附加说明
}

// Parser AST 静态语法树分析器
type Parser struct {
	fset *token.FileSet
}

func NewParser() *Parser {
	return &Parser{fset: token.NewFileSet()}
}

// ParseDir 递归扫描目录，一次性返回提取的所有端点与请求模型
func (p *Parser) ParseDir(dir string) ([]Endpoint, map[string]*StructDef, error) {
	var endpoints []Endpoint
	structs := make(map[string]*StructDef)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(p.fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}

		// 1. 扫描当前文件中的结构体定义
		for name, def := range extractStructs(file) {
			structs[name] = def
		}

		// 2. 扫描当前文件中的路由声明
		endpoints = append(endpoints, p.parseFile(file)...)
		return nil
	})

	return endpoints, structs, err
}

func (p *Parser) parseFile(file *ast.File) []Endpoint {
	var endpoints []Endpoint
	defaultTag := extractDefaultGroupTag(file)

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		// 提取该函数体内的路由前缀映射 (如 g := server.Group("/api/role"))
		groupVars := make(map[string]string)

		for _, stmt := range fn.Body.List {
			switch s := stmt.(type) {
			case *ast.AssignStmt:
				if ident, prefix, ok := parseGroupAssignment(s); ok {
					groupVars[ident] = prefix
				}
			case *ast.ExprStmt:
				if ep, ok := parseRouteStatement(s, groupVars, defaultTag); ok {
					endpoints = append(endpoints, ep)
				}
			}
		}
	}

	return endpoints
}

func parseGroupAssignment(assign *ast.AssignStmt) (string, string, bool) {
	if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return "", "", false
	}
	ident, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return "", "", false
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return "", "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Group" || len(call.Args) == 0 {
		return "", "", false
	}

	prefix := extractString(call.Args[0])
	return ident.Name, prefix, prefix != ""
}

func parseRouteStatement(stmt *ast.ExprStmt, groupVars map[string]string, defaultTag string) (Endpoint, bool) {
	call, ok := stmt.X.(*ast.CallExpr)
	if !ok {
		return Endpoint{}, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return Endpoint{}, false
	}

	method := strings.ToUpper(sel.Sel.Name)
	if !slices.Contains(validHTTPMethods, method) || len(call.Args) < 2 {
		return Endpoint{}, false
	}

	receiverIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return Endpoint{}, false
	}

	subPath := extractString(call.Args[0])
	basePath := groupVars[receiverIdent.Name]
	fullPath := cleanPath(basePath + subPath)

	ep := parseEndpointChain(call.Args[1], method, fullPath, defaultTag)
	return ep, ep.Path != ""
}

func parseEndpointChain(expr ast.Expr, method, path, defaultTag string) Endpoint {
	ep := Endpoint{
		Method: method,
		Path:   path,
		Tag:    defaultTag,
	}

	curr, ok := expr.(*ast.CallExpr)
	for ok && curr != nil {
		sel, isSel := curr.Fun.(*ast.SelectorExpr)
		if !isSel {
			break
		}

		switch sel.Sel.Name {
		case "Define", "Capability":
			if len(curr.Args) >= 1 {
				ep.Summary = extractString(curr.Args[0])
			}
			if len(curr.Args) >= 2 {
				ep.Description = fmt.Sprintf("权限标识: %s", extractString(curr.Args[1]))
			}
		case "Bind", "Handle":
			if len(curr.Args) > 0 {
				ep.ReqType = extractReqType(curr.Args[0])
			}
		case "Sub":
			if len(curr.Args) >= 2 {
				if subGroup := extractString(curr.Args[1]); subGroup != "" {
					ep.Tag = subGroup
				}
			}
		}

		curr, ok = sel.X.(*ast.CallExpr)
	}

	if ep.Summary == "" {
		ep.Summary = filepath.Base(path)
	}

	return ep
}

func extractStructs(file *ast.File) map[string]*StructDef {
	defs := make(map[string]*StructDef)

	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}

		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			def := &StructDef{Name: typeSpec.Name.Name}
			for _, field := range structType.Fields.List {
				tagStr := ""
				if field.Tag != nil {
					tagStr = field.Tag.Value
				}

				jsonName, required := parseFieldTags(tagStr)
				if jsonName == "-" {
					continue
				}

				fieldName := jsonName
				if fieldName == "" && len(field.Names) > 0 {
					fieldName = toLowerCamel(field.Names[0].Name)
				}
				if fieldName == "" {
					continue
				}

				def.Fields = append(def.Fields, StructField{
					Name:     fieldName,
					Type:     typeExprToString(field.Type),
					Required: required,
					Doc:      extractFieldDoc(field),
				})
			}

			defs[def.Name] = def
		}
	}

	return defs
}

func parseFieldTags(tagLiteral string) (jsonName string, required bool) {
	if tagLiteral == "" {
		return "", false
	}
	s, err := strconv.Unquote(tagLiteral)
	if err != nil {
		s = tagLiteral
	}

	tag := reflect.StructTag(s)
	jsonVal := tag.Get("json")
	if jsonVal != "" {
		parts := strings.Split(jsonVal, ",")
		jsonName = strings.TrimSpace(parts[0])
	}

	bindingVal := tag.Get("binding")
	required = strings.Contains(bindingVal, "required")
	return jsonName, required
}

func extractFieldDoc(field *ast.Field) string {
	if field.Doc != nil && len(field.Doc.List) > 0 {
		return strings.TrimSpace(strings.TrimPrefix(field.Doc.List[0].Text, "//"))
	}
	if field.Comment != nil && len(field.Comment.List) > 0 {
		return strings.TrimSpace(strings.TrimPrefix(field.Comment.List[0].Text, "//"))
	}
	return ""
}

func typeExprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.ArrayType:
		return "[]" + typeExprToString(e.Elt)
	case *ast.SelectorExpr:
		return typeExprToString(e.X) + "." + e.Sel.Name
	case *ast.StarExpr:
		return typeExprToString(e.X)
	}
	return "any"
}

func toLowerCamel(s string) string {
	if s == "" {
		return ""
	}
	r := []rune(s)
	r[0] = unicode.ToLower(r[0])
	return string(r)
}

func extractDefaultGroupTag(file *ast.File) string {
	var tag string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "NewRegistry" && len(call.Args) >= 3 {
			tag = extractString(call.Args[2])
			return false
		}
		return true
	})
	if tag == "" {
		tag = file.Name.Name
	}
	return tag
}

func extractReqType(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}
	if indexExpr, ok := call.Fun.(*ast.IndexExpr); ok {
		if ident, ok := indexExpr.Index.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}

func extractString(expr ast.Expr) string {
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		s, err := strconv.Unquote(lit.Value)
		if err == nil {
			return s
		}
	}
	return ""
}

func cleanPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.ReplaceAll(p, "//", "/")
}
