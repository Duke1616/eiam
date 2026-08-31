package authz

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/samber/lo"
)

//go:embed rego/policy.rego
var policyContent string

const capabilityVisibilityProfile pbac.FilterProfile = "eiam_capability_visibility"

type IAuthorizer interface {
	// Authorize 单一资源鉴权接口
	Authorize(ctx context.Context, input AuthInput) (bool, error)
	// Decide 对单一资源执行 OPA 鉴权，并返回由业务层消费的结构化 AccessScope。
	Decide(ctx context.Context, input AuthInput) (pbac.Decision, error)
	// AuthorizeBatch 批量资源判定接口，返回允许访问的资源 URN 列表
	AuthorizeBatch(ctx context.Context, input AuthInput) ([]string, error)
}

// AuthInput OPA 鉴权的输入结构体
type AuthInput struct {
	Actions         []string                  `json:"actions"`          // 通用动作 (单一判定用)
	Resource        string                    `json:"resource"`         // 单一资源 URN
	BatchResources  []string                  `json:"batch_resources"`  // 批量资源 URN 列表
	ResourceActions map[string][]string       `json:"resource_actions"` // 资源到动作的映射 (批量判定用)
	Policies        []domain.Policy           `json:"policies"`         // 策略文档全集
	Attributes      map[pbac.AttributeKey]any `json:"attributes,omitempty"`
	FilterProfile   pbac.FilterProfile        `json:"-"`
}

type OPAAuthorizer struct {
	query         rego.PreparedEvalQuery
	batchQuery    rego.PreparedEvalQuery
	matchingQuery rego.PreparedEvalQuery
}

type statementRef struct {
	PolicyIndex    int `json:"policy_index"`
	StatementIndex int `json:"statement_index"`
}

// NewOPAAuthorizer 初始化 OPA 鉴权器
func NewOPAAuthorizer(ctx context.Context) (IAuthorizer, error) {
	// 1. 编译单一判定查询
	r := rego.New(
		rego.Query("data.iam.authz.allow"),
		rego.Module("policy.rego", policyContent),
	)
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA allow query: %w", err)
	}

	// 2. 编译批量判定查询
	rb := rego.New(
		rego.Query("data.iam.authz.allowed_resources"),
		rego.Module("policy.rego", policyContent),
	)
	batchQuery, err := rb.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA batch query: %w", err)
	}
	rm := rego.New(
		rego.Query("data.iam.authz.matching_statement_refs"),
		rego.Module("policy.rego", policyContent),
	)
	matchingQuery, err := rm.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA statement query: %w", err)
	}

	return &OPAAuthorizer{
		query:         query,
		batchQuery:    batchQuery,
		matchingQuery: matchingQuery,
	}, nil
}

// Authorize 执行单一资源鉴权逻辑
func (o *OPAAuthorizer) Authorize(ctx context.Context, input AuthInput) (bool, error) {
	decision, err := o.Decide(ctx, input)
	return decision.Allowed, err
}

// Decide 保留 OPA 对 Action 和 Resource 的匹配职责，在 Go 中求值 Condition 并解析 AccessScope。
func (o *OPAAuthorizer) Decide(ctx context.Context, input AuthInput) (pbac.Decision, error) {
	// 零信任短路保护：无策略文档时默认隐式拒绝，无需调用 OPA 引擎
	if len(input.Policies) == 0 {
		return pbac.Decision{
			Allowed:    false,
			ReasonCode: pbac.ReasonNoMatchingAllow,
			Reason:     "no matching allow statement",
		}, nil
	}

	if !requiresExtendedEvaluation(input.Policies) {
		allowed, err := o.authorizeOPA(ctx, input)
		return pbac.Decision{Allowed: allowed, FilterProfile: input.FilterProfile}, err
	}
	statements, err := o.matchingStatements(ctx, input)
	if err != nil {
		return pbac.Decision{}, err
	}
	var allowAll bool
	var allowAccessScopes []*pbac.AccessScope
	var denyAccessScopes []*pbac.AccessScope
	for _, statement := range statements {
		conditionMatched, err := pbac.EvaluateCondition(statement.Condition, input.Attributes)
		if err != nil {
			return pbac.Decision{}, fmt.Errorf("evaluate condition: %w", err)
		}
		if !conditionMatched {
			continue
		}
		result, err := pbac.PartialEvaluateAccessScope(statement.AccessScope, input.Attributes)
		if err != nil {
			return pbac.Decision{}, fmt.Errorf("evaluate access scope: %w", err)
		}
		if result.IsFalse() {
			continue
		}
		if statement.Effect == domain.Deny {
			if result.IsTrue() {
				return pbac.Decision{ReasonCode: pbac.ReasonExplicitDeny, Reason: "explicit deny"}, nil
			}
			denyAccessScopes = append(denyAccessScopes, result.Residual())
			continue
		}
		if statement.Effect != domain.Allow {
			continue
		}
		if result.IsTrue() {
			allowAll = true
		} else {
			allowAccessScopes = append(allowAccessScopes, result.Residual())
		}
	}
	if !allowAll && len(allowAccessScopes) == 0 {
		return pbac.Decision{ReasonCode: pbac.ReasonNoMatchingAllow, Reason: "no matching allow statement"}, nil
	}
	if input.FilterProfile == "" && (!allowAll || len(denyAccessScopes) > 0) {
		return pbac.Decision{ReasonCode: pbac.ReasonAccessScopeUnsupported, Reason: "API asset has no AccessScope profile"}, nil
	}
	decision := pbac.Decision{
		Allowed:         true,
		FilterProfile:   input.FilterProfile,
		DenyAccessScope: pbac.AnyOf(denyAccessScopes),
	}
	if !allowAll {
		decision.AllowAccessScope = pbac.AnyOf(allowAccessScopes)
	}
	return decision, nil
}

func (o *OPAAuthorizer) authorizeOPA(ctx context.Context, input AuthInput) (bool, error) {
	results, err := o.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, fmt.Errorf("failed to evaluate OPA policy: %w", err)
	}
	// 利用 OPA 原生提供的 ResultSet.Allowed() 安全提取单一布尔判定结果
	return results.Allowed(), nil
}

func requiresExtendedEvaluation(policies []domain.Policy) bool {
	return lo.SomeBy(policies, func(policy domain.Policy) bool {
		return lo.SomeBy(policy.Statement, func(statement domain.Statement) bool {
			return statement.Condition != nil || statement.AccessScope != nil
		})
	})
}

func (o *OPAAuthorizer) matchingStatements(ctx context.Context, input AuthInput) ([]domain.Statement, error) {
	results, err := o.matchingQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("failed to match OPA statements: %w", err)
	}
	raw, ok := extractSlice(results)
	if !ok || len(raw) == 0 {
		return nil, nil
	}
	return lo.MapErr(raw, func(value any, _ int) (domain.Statement, error) {
		ref, err := decodeStatementRef(value)
		if err != nil {
			return domain.Statement{}, err
		}
		if ref.PolicyIndex < 0 || ref.PolicyIndex >= len(input.Policies) ||
			ref.StatementIndex < 0 || ref.StatementIndex >= len(input.Policies[ref.PolicyIndex].Statement) {
			return domain.Statement{}, fmt.Errorf("OPA statement reference is out of range: %#v", ref)
		}
		return input.Policies[ref.PolicyIndex].Statement[ref.StatementIndex], nil
	})
}

func decodeStatementRef(value any) (statementRef, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return statementRef{}, fmt.Errorf("invalid statement ref: expected map, got %T", value)
	}

	pIdx, ok1 := toInt(m["policy_index"])
	sIdx, ok2 := toInt(m["statement_index"])
	if !ok1 || !ok2 {
		return statementRef{}, fmt.Errorf("invalid statement ref indices: %#v", m)
	}

	return statementRef{PolicyIndex: pIdx, StatementIndex: sIdx}, nil
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}

// AuthorizeBatch 批量执行 OPA 鉴权，返回允许访问的 URN 集合
func (o *OPAAuthorizer) AuthorizeBatch(ctx context.Context, input AuthInput) ([]string, error) {
	// 快速短路：资源列表为空或无策略文档时直接返回空列表，免除 OPA 引擎编译与计算开销
	if len(input.BatchResources) == 0 || len(input.Policies) == 0 {
		return []string{}, nil
	}

	if requiresExtendedEvaluation(input.Policies) {
		allowed := make([]string, 0, len(input.BatchResources))
		for _, resource := range input.BatchResources {
			decision, err := o.Decide(ctx, AuthInput{
				Actions:       input.ResourceActions[resource],
				Resource:      resource,
				Policies:      input.Policies,
				Attributes:    input.Attributes,
				FilterProfile: capabilityVisibilityProfile,
			})
			if err != nil {
				return nil, err
			}
			if decision.Allowed {
				allowed = append(allowed, resource)
			}
		}
		return allowed, nil
	}
	results, err := o.batchQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate OPA batch policy: %w", err)
	}
	return extractStringSlice(results), nil
}

// extractSlice 安全提取 OPA 查询结果中的元素切片，避免深层链式索引与空指针风险
func extractSlice(rs rego.ResultSet) ([]any, bool) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, false
	}
	s, ok := rs[0].Expressions[0].Value.([]any)
	return s, ok
}

// extractStringSlice 安全提取 OPA 集合查询结果中的字符串切片
func extractStringSlice(rs rego.ResultSet) []string {
	raw, ok := extractSlice(rs)
	if !ok || len(raw) == 0 {
		return []string{}
	}
	return lo.FilterMap(raw, func(v any, _ int) (string, bool) {
		s, ok := v.(string)
		return s, ok
	})
}
