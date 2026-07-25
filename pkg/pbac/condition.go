package pbac

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Operator 定义 Predicate 支持的比较语义。
type Operator string

// Operator 支持的字符串、集合、数值、时间与网络比较操作。
const (
	StringEquals                Operator = "StringEquals"
	StringNotEquals             Operator = "StringNotEquals"
	StringEqualsIgnoreCase      Operator = "StringEqualsIgnoreCase"
	StringContains              Operator = "StringContains"
	ForAnyValueStringEquals     Operator = "ForAnyValue:StringEquals"
	ForAllValuesStringNotEquals Operator = "ForAllValues:StringNotEquals"
	NumericEquals               Operator = "NumericEquals"
	NumericLessThan             Operator = "NumericLessThan"
	NumericGreaterThan          Operator = "NumericGreaterThan"
	Bool                        Operator = "Bool"
	DateLessThan                Operator = "DateLessThan"
	DateGreaterThan             Operator = "DateGreaterThan"
	IpAddress                   Operator = "IpAddress"
	NotIpAddress                Operator = "NotIpAddress"
)

// OperandType 区分固定字面量与属性引用。
type OperandType string

// AttributeKey 是 Condition 属性的稳定命名键。
type AttributeKey string

// FilterProfile 标识 API 的 AccessScope 与业务查询共同遵循的编译契约。
type FilterProfile string

// ReasonCode 标识授权拒绝或求值失败的机器可读原因。
type ReasonCode string

// OperandType 支持的值来源类型。
const (
	OperandLiteral OperandType = "literal"
	OperandRef     OperandType = "ref"
)

// ReasonCode 预定义的授权决策原因。
const (
	ReasonNoMatchingAllow        ReasonCode = "no_matching_allow"
	ReasonExplicitDeny           ReasonCode = "explicit_deny"
	ReasonAccessScopeUnsupported ReasonCode = "access_scope_unsupported"
	ReasonAssetUnbound           ReasonCode = "asset_unbound"
	ReasonEvaluationError        ReasonCode = "evaluation_error"
)

// Condition 是有界的布尔表达式树，每个节点只能包含 all、any 或 predicate 之一。
type Condition struct {
	All       []Condition `json:"all,omitempty"`
	Any       []Condition `json:"any,omitempty"`
	Predicate *Predicate  `json:"predicate,omitempty"`
}

// AccessScope 描述由业务数据源求值的数据范围表达式。
// 它与 Condition 复用同一套有界 AST，但两者允许的属性命名空间不同。
type AccessScope = Condition

// AccessScopePreset 是业务服务声明的、可直接用于策略编辑器的数据访问范围模板。
// EIAM 只校验和透传表达式，不解释其中的业务属性，也不参与 SQL 编译。
type AccessScopePreset struct {
	Code        string       `json:"code"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Expression  *AccessScope `json:"expression"`
}

// Predicate 描述一个属性、操作符及其期望值。
type Predicate struct {
	Key      AttributeKey `json:"key"`
	Operator Operator     `json:"operator"`
	Values   []Operand    `json:"values"`
}

// Operand 表示 Predicate 的字面量或另一个属性的引用。
type Operand struct {
	Type  OperandType `json:"type"`
	Value any         `json:"value"`
}

// Literal 构造固定值 Operand。
func Literal(value any) Operand {
	return Operand{Type: OperandLiteral, Value: value}
}

// Ref 构造在 EIAM 中解析的属性引用 Operand。
func Ref(key AttributeKey) Operand {
	return Operand{Type: OperandRef, Value: key}
}

// Decision 是 EIAM 返回给 SDK 的授权结果和残余 AccessScope。
type Decision struct {
	Allowed          bool          `json:"allowed"`
	ReasonCode       ReasonCode    `json:"reason_code,omitempty"`
	Reason           string        `json:"reason,omitempty"`
	AllowAccessScope *AccessScope  `json:"allow_access_scope,omitempty"`
	DenyAccessScope  *AccessScope  `json:"deny_access_scope,omitempty"`
	FilterProfile    FilterProfile `json:"filter_profile,omitempty"`
}

type evaluationState uint8

const (
	stateFalse evaluationState = iota
	stateTrue
	stateResidual
	maxConditionDepth      = 4
	maxConditionPredicates = 32
	maxPredicateValues     = 100
)

// EvaluationResult 表示表达式已匹配、未匹配或仍需业务查询求值。
type EvaluationResult struct {
	state    evaluationState
	residual *Condition
}

// IsFalse 表示表达式已在 EIAM 中确定为不匹配。
func (r EvaluationResult) IsFalse() bool { return r.state == stateFalse }

// IsTrue 表示表达式已在 EIAM 中确定为匹配。
func (r EvaluationResult) IsTrue() bool { return r.state == stateTrue }

// Residual 返回仍需业务数据源求值的表达式；没有残余条件时返回 nil。
func (r EvaluationResult) Residual() *Condition { return r.residual }

var supportedOperators = map[Operator]struct{}{
	StringEquals:                {},
	StringNotEquals:             {},
	StringEqualsIgnoreCase:      {},
	StringContains:              {},
	ForAnyValueStringEquals:     {},
	ForAllValuesStringNotEquals: {},
	NumericEquals:               {},
	NumericLessThan:             {},
	NumericGreaterThan:          {},
	Bool:                        {},
	DateLessThan:                {},
	DateGreaterThan:             {},
	IpAddress:                   {},
	NotIpAddress:                {},
}

// Validate 校验 Condition/AccessScope 的结构、复杂度、操作符和 Operand 类型。
func Validate(condition *Condition) error {
	if condition == nil {
		return nil
	}
	count := 0
	return validateNode(condition, 1, &count)
}

// ValidateCondition 校验授权条件只能使用 EIAM 可立即求值的属性。
func ValidateCondition(condition *Condition) error {
	if err := Validate(condition); err != nil {
		return err
	}
	return validateAttributeNamespaces(condition, true)
}

// ValidateAccessScope 校验数据范围只能使用业务属性，并且引用值来自 EIAM 可信属性。
func ValidateAccessScope(scope *AccessScope) error {
	if err := Validate(scope); err != nil {
		return err
	}
	return validateAttributeNamespaces(scope, false)
}

func validateAttributeNamespaces(expression *Condition, immediate bool) error {
	if expression == nil {
		return nil
	}
	if expression.Predicate != nil {
		predicate := expression.Predicate
		if immediate && !isImmediateAttribute(predicate.Key) {
			return fmt.Errorf("condition key %q is not an EIAM attribute", predicate.Key)
		}
		if !immediate && isReservedAttributeKey(predicate.Key) {
			return fmt.Errorf("access scope key %q must be a business attribute", predicate.Key)
		}
		for _, operand := range predicate.Values {
			if operand.Type != OperandRef {
				continue
			}
			ref, _ := operandReference(operand)
			if !isImmediateAttribute(ref) {
				return fmt.Errorf("reference %q is not an EIAM attribute", ref)
			}
		}
		return nil
	}
	for i := range expression.All {
		if err := validateAttributeNamespaces(&expression.All[i], immediate); err != nil {
			return err
		}
	}
	for i := range expression.Any {
		if err := validateAttributeNamespaces(&expression.Any[i], immediate); err != nil {
			return err
		}
	}
	return nil
}

func isReservedAttributeKey(key AttributeKey) bool {
	value := string(key)
	return strings.HasPrefix(value, "principal:") ||
		strings.HasPrefix(value, "environment:") ||
		strings.HasPrefix(value, "request:") ||
		strings.HasPrefix(value, "auth:")
}

func validateNode(condition *Condition, depth int, count *int) error {
	if depth > maxConditionDepth {
		return fmt.Errorf("condition depth exceeds %d", maxConditionDepth)
	}
	kinds := 0
	if len(condition.All) > 0 {
		kinds++
	}
	if len(condition.Any) > 0 {
		kinds++
	}
	if condition.Predicate != nil {
		kinds++
	}
	if kinds != 1 {
		return errors.New("expression node must contain exactly one of all, any or predicate")
	}
	for i := range condition.All {
		if err := validateNode(&condition.All[i], depth+1, count); err != nil {
			return err
		}
	}
	for i := range condition.Any {
		if err := validateNode(&condition.Any[i], depth+1, count); err != nil {
			return err
		}
	}
	if condition.Predicate == nil {
		return nil
	}
	(*count)++
	if *count > maxConditionPredicates {
		return fmt.Errorf("condition predicates exceed %d", maxConditionPredicates)
	}
	predicate := condition.Predicate
	if strings.TrimSpace(string(predicate.Key)) == "" {
		return errors.New("condition predicate key is required")
	}
	if _, ok := supportedOperators[predicate.Operator]; !ok {
		return fmt.Errorf("unsupported condition operator %q", predicate.Operator)
	}
	if len(predicate.Values) == 0 || len(predicate.Values) > maxPredicateValues {
		return fmt.Errorf("condition predicate values must contain 1 to %d entries", maxPredicateValues)
	}
	for _, operand := range predicate.Values {
		if operand.Type != OperandLiteral && operand.Type != OperandRef {
			return fmt.Errorf("unsupported operand type %q", operand.Type)
		}
		if operand.Type == OperandRef {
			ref, ok := operandReference(operand)
			if !ok || strings.TrimSpace(string(ref)) == "" {
				return errors.New("reference operand must be a non-empty attribute key")
			}
		}
	}
	return nil
}

// EvaluateCondition 使用 EIAM 可信属性完整求值授权条件。
func EvaluateCondition(
	condition *Condition,
	attributes map[AttributeKey]any,
) (bool, error) {
	if condition == nil {
		return true, nil
	}
	if err := ValidateCondition(condition); err != nil {
		return false, err
	}
	result, err := evaluateNode(condition, attributes)
	if err != nil {
		return false, err
	}
	if result.Residual() != nil {
		return false, errors.New("condition evaluation produced an unexpected residual")
	}
	return result.IsTrue(), nil
}

// PartialEvaluateAccessScope 解析可信属性引用，并返回由业务数据源求值的残余 AccessScope。
func PartialEvaluateAccessScope(
	scope *AccessScope,
	attributes map[AttributeKey]any,
) (EvaluationResult, error) {
	if scope == nil {
		return EvaluationResult{state: stateTrue}, nil
	}
	if err := ValidateAccessScope(scope); err != nil {
		return EvaluationResult{state: stateFalse}, err
	}
	return evaluateNode(scope, attributes)
}

func evaluateNode(condition *Condition, attributes map[AttributeKey]any) (EvaluationResult, error) {
	if condition.Predicate != nil {
		return evaluatePredicate(condition.Predicate, attributes)
	}
	items, all := condition.Any, false
	if len(condition.All) > 0 {
		items, all = condition.All, true
	}
	residuals := make([]Condition, 0, len(items))
	for i := range items {
		result, err := evaluateNode(&items[i], attributes)
		if err != nil {
			return EvaluationResult{state: stateFalse}, err
		}
		if all && result.IsFalse() {
			return result, nil
		}
		if !all && result.IsTrue() {
			return result, nil
		}
		if result.Residual() != nil {
			residuals = append(residuals, *result.Residual())
		}
	}
	if len(residuals) == 0 {
		if all {
			return EvaluationResult{state: stateTrue}, nil
		}
		return EvaluationResult{state: stateFalse}, nil
	}
	if len(residuals) == 1 {
		return EvaluationResult{state: stateResidual, residual: &residuals[0]}, nil
	}
	residual := &Condition{}
	if all {
		residual.All = residuals
	} else {
		residual.Any = residuals
	}
	return EvaluationResult{state: stateResidual, residual: residual}, nil
}

func evaluatePredicate(predicate *Predicate, attributes map[AttributeKey]any) (EvaluationResult, error) {
	values := make([]Operand, 0, len(predicate.Values))
	for _, operand := range predicate.Values {
		if operand.Type != OperandRef {
			values = append(values, operand)
			continue
		}
		ref, _ := operandReference(operand)
		value, ok := attributes[ref]
		if !ok {
			if isImmediateAttribute(ref) {
				return EvaluationResult{state: stateFalse}, nil
			}
			return EvaluationResult{state: stateFalse}, fmt.Errorf("condition reference %q is unavailable", ref)
		}
		values = append(values, Literal(value))
	}
	lhs, exists := attributes[predicate.Key]
	if !exists {
		if isImmediateAttribute(predicate.Key) {
			return EvaluationResult{state: stateFalse}, nil
		}
		return EvaluationResult{
			state: stateResidual,
			residual: &Condition{Predicate: &Predicate{
				Key:      predicate.Key,
				Operator: predicate.Operator,
				Values:   values,
			}},
		}, nil
	}
	matched, err := compare(lhs, predicate.Operator, values)
	if err != nil {
		return EvaluationResult{state: stateFalse}, err
	}
	if matched {
		return EvaluationResult{state: stateTrue}, nil
	}
	return EvaluationResult{state: stateFalse}, nil
}

func operandReference(operand Operand) (AttributeKey, bool) {
	switch value := operand.Value.(type) {
	case string:
		return AttributeKey(value), true
	case AttributeKey:
		return value, true
	default:
		return "", false
	}
}

func compare(lhs any, operator Operator, operands []Operand) (bool, error) {
	values := flatten(lhs)
	negative := operator == StringNotEquals || operator == ForAllValuesStringNotEquals || operator == NotIpAddress
	if negative {
		for _, value := range values {
			matched, err := compareScalar(value, operator, operands)
			if err != nil || !matched {
				return false, err
			}
		}
		return true, nil
	}
	for _, value := range values {
		matched, err := compareScalar(value, operator, operands)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func flatten(value any) []any {
	rv := reflect.ValueOf(value)
	if !rv.IsValid() || (rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array) {
		return []any{value}
	}
	result := make([]any, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		result = append(result, rv.Index(i).Interface())
	}
	return result
}

func compareScalar(lhs any, operator Operator, operands []Operand) (bool, error) {
	negative := operator == StringNotEquals || operator == ForAllValuesStringNotEquals || operator == NotIpAddress
	if negative {
		for _, operand := range operands {
			matched, err := comparePair(lhs, operand.Value, operator)
			if err != nil || matched {
				return false, err
			}
		}
		return true, nil
	}
	for _, operand := range operands {
		matched, err := comparePair(lhs, operand.Value, operator)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func comparePair(lhs, rhs any, operator Operator) (bool, error) {
	switch operator {
	case StringEquals, StringNotEquals, ForAnyValueStringEquals, ForAllValuesStringNotEquals:
		return fmt.Sprint(lhs) == fmt.Sprint(rhs), nil
	case StringEqualsIgnoreCase:
		return strings.EqualFold(fmt.Sprint(lhs), fmt.Sprint(rhs)), nil
	case StringContains:
		return strings.Contains(fmt.Sprint(lhs), fmt.Sprint(rhs)), nil
	case Bool:
		left, err := strconv.ParseBool(fmt.Sprint(lhs))
		if err != nil {
			return false, err
		}
		right, err := strconv.ParseBool(fmt.Sprint(rhs))
		return left == right, err
	case NumericEquals, NumericLessThan, NumericGreaterThan:
		left, err := strconv.ParseFloat(fmt.Sprint(lhs), 64)
		if err != nil {
			return false, err
		}
		right, err := strconv.ParseFloat(fmt.Sprint(rhs), 64)
		if err != nil {
			return false, err
		}
		if operator == NumericEquals {
			return left == right, nil
		}
		if operator == NumericLessThan {
			return left < right, nil
		}
		return left > right, nil
	case DateLessThan, DateGreaterThan:
		left, err := time.Parse(time.RFC3339, fmt.Sprint(lhs))
		if err != nil {
			return false, err
		}
		right, err := time.Parse(time.RFC3339, fmt.Sprint(rhs))
		if err != nil {
			return false, err
		}
		if operator == DateLessThan {
			return left.Before(right), nil
		}
		return left.After(right), nil
	case IpAddress, NotIpAddress:
		address, err := netip.ParseAddr(fmt.Sprint(lhs))
		if err != nil {
			return false, err
		}
		expected := fmt.Sprint(rhs)
		if prefix, prefixErr := netip.ParsePrefix(expected); prefixErr == nil {
			return prefix.Contains(address), nil
		}
		other, err := netip.ParseAddr(expected)
		return address == other, err
	default:
		return false, fmt.Errorf("unsupported condition operator %q", operator)
	}
}

// AnyOf 将非空 Condition 合并为逻辑 OR，并折叠空集合和单元素集合。
func AnyOf(conditions []*Condition) *Condition {
	items := make([]Condition, 0, len(conditions))
	for _, condition := range conditions {
		if condition != nil {
			items = append(items, *condition)
		}
	}
	if len(items) == 0 {
		return nil
	}
	if len(items) == 1 {
		return &items[0]
	}
	return &Condition{Any: items}
}

type decisionContextKey struct{}

// WithDecision 将已验证的 PBAC 决策写入业务请求上下文。
func WithDecision(ctx context.Context, decision Decision) context.Context {
	return context.WithValue(ctx, decisionContextKey{}, decision)
}

// DecisionFromContext 从业务请求上下文读取 SDK 注入的 PBAC 决策。
func DecisionFromContext(ctx context.Context) (Decision, bool) {
	if ctx == nil {
		return Decision{}, false
	}
	decision, ok := ctx.Value(decisionContextKey{}).(Decision)
	return decision, ok
}
