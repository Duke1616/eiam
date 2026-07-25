package authz

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/open-policy-agent/opa/v1/rego"
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

	if len(results) == 0 {
		return false, nil
	}

	allow, ok := results[0].Expressions[0].Value.(bool)
	return ok && allow, nil
}

func requiresExtendedEvaluation(policies []domain.Policy) bool {
	for _, policy := range policies {
		for _, statement := range policy.Statement {
			if statement.Condition != nil || statement.AccessScope != nil {
				return true
			}
		}
	}
	return false
}

func (o *OPAAuthorizer) matchingStatements(ctx context.Context, input AuthInput) ([]domain.Statement, error) {
	results, err := o.matchingQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("failed to match OPA statements: %w", err)
	}
	if len(results) == 0 {
		return nil, nil
	}
	raw, ok := results[0].Expressions[0].Value.([]interface{})
	if !ok {
		return nil, errors.New("OPA statement matching returned an invalid result")
	}
	statements := make([]domain.Statement, 0, len(raw))
	for _, value := range raw {
		ref, err := decodeStatementRef(value)
		if err != nil {
			return nil, err
		}
		if ref.PolicyIndex < 0 || ref.PolicyIndex >= len(input.Policies) ||
			ref.StatementIndex < 0 || ref.StatementIndex >= len(input.Policies[ref.PolicyIndex].Statement) {
			return nil, fmt.Errorf("OPA statement reference is out of range: %#v", ref)
		}
		statements = append(statements, input.Policies[ref.PolicyIndex].Statement[ref.StatementIndex])
	}
	return statements, nil
}

func decodeStatementRef(value any) (statementRef, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return statementRef{}, fmt.Errorf("encode OPA statement reference: %w", err)
	}
	var ref statementRef
	if err = json.Unmarshal(data, &ref); err != nil {
		return statementRef{}, fmt.Errorf("decode OPA statement reference: %w", err)
	}
	return ref, nil
}

// AuthorizeBatch 批量执行 OPA 鉴权，返回允许访问的 URN 集合
func (o *OPAAuthorizer) AuthorizeBatch(ctx context.Context, input AuthInput) ([]string, error) {
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

	if len(results) == 0 {
		return []string{}, nil
	}

	// OPA 集合查询结果通常是一个接口类型的切片，其值是 URN 字符串
	rawRes, ok := results[0].Expressions[0].Value.([]interface{})
	if !ok {
		return []string{}, nil
	}

	res := make([]string, 0, len(rawRes))
	for _, raw := range rawRes {
		if s, ok := raw.(string); ok {
			res = append(res, s)
		}
	}

	return res, nil
}
