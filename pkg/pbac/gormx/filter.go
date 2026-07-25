package gormx

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Duke1616/eiam/pkg/pbac"
	"gorm.io/gorm"
)

// ErrDecisionMissing 表示业务请求上下文中没有经过 SDK 验证的 PBAC 决策。
var ErrDecisionMissing = errors.New("PBAC decision is missing")

// Expression 是已参数化的 GORM WHERE 表达式。
type Expression struct {
	SQL  string
	Args []any
}

// Profile 将固定 profile 名称绑定到业务受控的 Predicate 编译器。
type Profile struct {
	Name             pbac.FilterProfile
	CompilePredicate func(*pbac.Predicate) (Expression, error)
}

// Apply 从上下文读取 PBAC 决策，校验 profile 后将过滤表达式应用到查询。
func Apply(ctx context.Context, db *gorm.DB, profile Profile) (*gorm.DB, error) {
	decision, ok := pbac.DecisionFromContext(ctx)
	if !ok {
		return nil, ErrDecisionMissing
	}
	expression, err := Compile(decision, profile)
	if err != nil {
		return nil, err
	}
	if expression.SQL == "" {
		return db, nil
	}
	return db.Where(expression.SQL, expression.Args...), nil
}

// Compile 将 Decision 中的 allow/deny AccessScope 编译为参数化表达式。
func Compile(decision pbac.Decision, profile Profile) (Expression, error) {
	if !decision.Allowed {
		return Expression{}, errors.New("PBAC decision denied access")
	}
	if profile.Name == "" || profile.CompilePredicate == nil {
		return Expression{}, errors.New("invalid PBAC filter profile")
	}
	if decision.FilterProfile != profile.Name {
		return Expression{}, fmt.Errorf("PBAC profile mismatch: decision=%q query=%q", decision.FilterProfile, profile.Name)
	}
	if err := pbac.ValidateAccessScope(decision.AllowAccessScope); err != nil {
		return Expression{}, fmt.Errorf("invalid allow access scope: %w", err)
	}
	if err := pbac.ValidateAccessScope(decision.DenyAccessScope); err != nil {
		return Expression{}, fmt.Errorf("invalid deny access scope: %w", err)
	}
	var expressions []Expression
	if decision.AllowAccessScope != nil {
		expression, err := compileAccessScope(decision.AllowAccessScope, profile)
		if err != nil {
			return Expression{}, err
		}
		expressions = append(expressions, Expression{SQL: "(" + expression.SQL + ")", Args: expression.Args})
	}
	if decision.DenyAccessScope != nil {
		expression, err := compileAccessScope(decision.DenyAccessScope, profile)
		if err != nil {
			return Expression{}, err
		}
		expressions = append(expressions, Expression{SQL: "NOT (" + expression.SQL + ")", Args: expression.Args})
	}
	return join(" AND ", expressions), nil
}

func compileAccessScope(scope *pbac.AccessScope, profile Profile) (Expression, error) {
	if scope.Predicate != nil {
		expression, err := profile.CompilePredicate(scope.Predicate)
		if err != nil {
			return Expression{}, err
		}
		if strings.TrimSpace(expression.SQL) == "" {
			return Expression{}, errors.New("empty predicate SQL expression")
		}
		return expression, nil
	}
	items, separator := scope.Any, " OR "
	if len(scope.All) > 0 {
		items, separator = scope.All, " AND "
	}
	expressions := make([]Expression, 0, len(items))
	for i := range items {
		expression, err := compileAccessScope(&items[i], profile)
		if err != nil {
			return Expression{}, err
		}
		expressions = append(expressions, Expression{SQL: "(" + expression.SQL + ")", Args: expression.Args})
	}
	return join(separator, expressions), nil
}

func join(separator string, expressions []Expression) Expression {
	clauses := make([]string, 0, len(expressions))
	var args []any
	for _, expression := range expressions {
		clauses = append(clauses, expression.SQL)
		args = append(args, expression.Args...)
	}
	return Expression{SQL: strings.Join(clauses, separator), Args: args}
}

// LiteralStrings 提取已解析的非空字符串 Operand，拒绝残留引用和其他类型。
func LiteralStrings(operands []pbac.Operand) ([]any, error) {
	values := make([]any, 0, len(operands))
	for _, operand := range operands {
		if operand.Type != pbac.OperandLiteral {
			return nil, errors.New("unresolved reference in residual AccessScope")
		}
		value, ok := operand.Value.(string)
		if !ok || value == "" {
			return nil, errors.New("access scope values must be non-empty strings")
		}
		values = append(values, value)
	}
	return values, nil
}

// Placeholders 返回指定数量的逗号分隔 GORM 参数占位符。
func Placeholders(count int) string { return strings.TrimSuffix(strings.Repeat("?,", count), ",") }
