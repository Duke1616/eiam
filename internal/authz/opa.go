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
    // Authorize 鉴权接口
    Authorize(ctx context.Context, input AuthInput) (bool, error)
}

// AuthInput OPA 鉴权的输入结构体
type AuthInput struct {
	Action   string          `json:"action"`   // 请求的操作, e.g. ecs:BatchValidate
	Resource string          `json:"resource"` // 操作的资源, e.g. arn:ecs:001
	Policies []domain.Policy `json:"policies"` // 用户拥有的所有策略列表
}

type OPAAuthorizer struct {
	query rego.PreparedEvalQuery
}

// NewOPAAuthorizer 初始化 OPA 鉴权器
func NewOPAAuthorizer(ctx context.Context) (*OPAAuthorizer, error) {
	r := rego.New(
		rego.Query("data.iam.authz.allow"),
		rego.Module("policy.rego", policyContent),
	)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	return &OPAAuthorizer{
		query: query,
	}, nil
}

// Authorize 执行 OPA 鉴权逻辑
func (o *OPAAuthorizer) Authorize(ctx context.Context, input AuthInput) (bool, error) {
	results, err := o.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, fmt.Errorf("failed to evaluate OPA policy: %w", err)
	}

	if len(results) == 0 {
		return false, nil
	}

	// 提取布尔值结果
	allow, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, nil
	}

	return allow, nil
}
