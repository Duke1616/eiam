package capability

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
)

// CallStep 链式调用中的单步调用单元
type CallStep struct {
	Receiver string     // 变量接收者名称 (如 ldap / capability.RoleModule)
	Method   string     // 调用的方法名 (如 Define / For / Sub / Needs)
	Args     []ast.Expr // 实参表达式列表
	Pos      token.Pos  // 源码位置
}

// CallChain 链式调用的顺序切片，封装高阶查询与元数据提取能力
type CallChain []CallStep

// UnwindCallChain 将深层嵌套的 AST 调用表达式展开为正序的 CallChain
func UnwindCallChain(call *ast.CallExpr) CallChain {
	var steps []CallStep
	curr := call

	for curr != nil {
		sel, ok := curr.Fun.(*ast.SelectorExpr)
		if !ok {
			if ident, ok := curr.Fun.(*ast.Ident); ok {
				steps = append(steps, CallStep{
					Method: ident.Name,
					Args:   curr.Args,
					Pos:    curr.Pos(),
				})
			}
			break
		}

		step := CallStep{
			Method: sel.Sel.Name,
			Args:   curr.Args,
			Pos:    sel.Pos(),
		}

		// 终结条件：接收者是普通标识符 (如 h / ldap) 或包选择器 (如 capability.RoleModule)
		if recvIdent, ok := sel.X.(*ast.Ident); ok {
			step.Receiver = recvIdent.Name
			steps = append(steps, step)
			break
		} else if recvSel, ok := sel.X.(*ast.SelectorExpr); ok {
			step.Receiver = recvSel.Sel.Name
			steps = append(steps, step)
			break
		}

		steps = append(steps, step)
		innerCall, ok := sel.X.(*ast.CallExpr)
		if !ok {
			break
		}
		curr = innerCall
	}

	return CallChain(steps)
}

// Find 查找指定方法列表中最先匹配的单步调用
func (c CallChain) Find(methods ...string) *CallStep {
	for i := range c {
		for _, m := range methods {
			if c[i].Method == m {
				return &c[i]
			}
		}
	}
	return nil
}

// Has 判断调用链中是否存在特定方法
func (c CallChain) Has(method string) bool {
	return c.Find(method) != nil
}

// ExtractTargetModel 提取跨领域挂载的目标领域名称 (如 h.For(model.Role) -> "role")
func (c CallChain) ExtractTargetModel() string {
	forStep := c.Find("For")
	if forStep != nil && len(forStep.Args) > 0 {
		return ExtractModelArg(forStep.Args[0])
	}
	return ""
}

// ExtractStringArg 安全提取指定方法的第 N 个字符串参数
func (c CallChain) ExtractStringArg(method string, index int) string {
	step := c.Find(method)
	if step == nil || len(step.Args) <= index {
		return ""
	}
	return ExtractString(step.Args[index])
}

// ExtractString 安全提取 AST 字面量字符串
func ExtractString(expr ast.Expr) string {
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		s, err := strconv.Unquote(lit.Value)
		if err == nil {
			return s
		}
	}
	return ""
}

// ExtractModelArg 提取 model.Xxx 或 Xxx 的蛇形领域名
func ExtractModelArg(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		return ToSnakeCase(e.Sel.Name)
	case *ast.Ident:
		return ToSnakeCase(e.Name)
	}
	return ""
}

// ExtractPermRef 提取 perm.User.Get 或 perm.Role.View 等强类型引用的完整权限码
func ExtractPermRef(service string, expr ast.Expr) string {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	action := ToSnakeCase(sel.Sel.Name)

	if parentSel, ok := sel.X.(*ast.SelectorExpr); ok {
		// 如 perm.User.Get -> module = "user"
		module := ToSnakeCase(parentSel.Sel.Name)
		return fmt.Sprintf("%s:%s:%s", service, module, action)
	}
	return ""
}

// ExtractScope 安全提取 Scope 作用域 (ScopeSystem / ScopeTenant)
func ExtractScope(expr ast.Expr) Scope {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		if e.Sel.Name == "ScopeSystem" {
			return ScopeSystem
		}
		return ScopeTenant
	case *ast.BasicLit:
		if s, err := strconv.Unquote(e.Value); err == nil && s == "system" {
			return ScopeSystem
		}
	}
	return ScopeTenant
}
