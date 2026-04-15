package authz

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/open-policy-agent/opa/v1/rego"
)

//go:embed rego/policy.rego
var policyContent string

type IAuthorizer interface {
	// Authorize 单一资源鉴权接口
	Authorize(ctx context.Context, input AuthInput) (bool, error)
	// AuthorizeBatch 批量资源判定接口，返回允许访问的资源 URN 列表
	AuthorizeBatch(ctx context.Context, input AuthInput) ([]string, error)
}

// AuthInput OPA 鉴权的输入结构体
type AuthInput struct {
	Actions         []string            `json:"actions"`          // 通用动作 (单一判定用)
	Resource        string              `json:"resource"`         // 单一资源 URN
	BatchResources  []string            `json:"batch_resources"`  // 批量资源 URN 列表
	ResourceActions map[string][]string `json:"resource_actions"` // 资源到动作的映射 (批量判定用)
	Policies        []domain.Policy     `json:"policies"`         // 策略文档全集
}

type OPAAuthorizer struct {
	query      rego.PreparedEvalQuery
	batchQuery rego.PreparedEvalQuery
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

	return &OPAAuthorizer{
		query:      query,
		batchQuery: batchQuery,
	}, nil
}

// Authorize 执行单一资源鉴权逻辑
func (o *OPAAuthorizer) Authorize(ctx context.Context, input AuthInput) (bool, error) {
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

// AuthorizeBatch 批量执行 OPA 鉴权，返回允许访问的 URN 集合
func (o *OPAAuthorizer) AuthorizeBatch(ctx context.Context, input AuthInput) ([]string, error) {
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
