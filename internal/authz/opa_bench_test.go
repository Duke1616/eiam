package authz

import (
	"context"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/pbac"
)

// BenchmarkOPA_Decide_Simple 基础策略准入判定性能（单核/串行）
func BenchmarkOPA_Decide_Simple(b *testing.B) {
	authorizer, err := NewOPAAuthorizer(context.Background())
	if err != nil {
		b.Fatal(err)
	}

	policy := domain.Policy{
		Statement: []domain.Statement{{
			Effect:   domain.Allow,
			Action:   []string{"user:view"},
			Resource: []string{"urn:iam:api:user:GET:/users"},
		}},
	}

	input := AuthInput{
		Actions:    []string{"user:view"},
		Resource:   "urn:iam:api:user:GET:/users",
		Policies:   []domain.Policy{policy},
		Attributes: map[pbac.AttributeKey]any{pbac.PrincipalUsername: "alice"},
	}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		decision, err := authorizer.Decide(ctx, input)
		if err != nil || !decision.Allowed {
			b.Fatalf("decide failed: allowed=%v, err=%v", decision.Allowed, err)
		}
	}
}

// BenchmarkOPA_Decide_ComplexPBAC 复杂 PBAC 策略评估（包含通配符匹配、Condition 条件与 AccessScope 数据范围派生）
func BenchmarkOPA_Decide_ComplexPBAC(b *testing.B) {
	authorizer, err := NewOPAAuthorizer(context.Background())
	if err != nil {
		b.Fatal(err)
	}

	policy := domain.Policy{
		Statement: []domain.Statement{
			// 1. 显式 Deny 防御规则 (优先级最高)
			{
				Effect:   domain.Deny,
				Action:   []string{"ticket:delete"},
				Resource: []string{"*"},
			},
			// 2. 带细粒度属性约束与数据范围的 Allow 规则
			{
				Effect:   domain.Allow,
				Action:   []string{"ticket:*"},
				Resource: []string{"*"},
				Condition: &pbac.Condition{
					Predicate: &pbac.Predicate{
						Key:      pbac.PrincipalUsername,
						Operator: pbac.StringEquals,
						Values:   []pbac.Operand{pbac.Literal("alice")},
					},
				},
				AccessScope: &pbac.AccessScope{
					Predicate: &pbac.Predicate{
						Key:      "ticket:create_by",
						Operator: pbac.StringEquals,
						Values:   []pbac.Operand{pbac.Ref(pbac.PrincipalUsername)},
					},
				},
			},
		},
	}

	input := AuthInput{
		Actions:       []string{"ticket:history"},
		Resource:      "ticket:api:get:/history",
		Policies:      []domain.Policy{policy},
		Attributes:    map[pbac.AttributeKey]any{pbac.PrincipalUsername: "alice"},
		FilterProfile: "ticket_history.v1",
	}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		decision, err := authorizer.Decide(ctx, input)
		if err != nil || !decision.Allowed {
			b.Fatalf("decide failed: allowed=%v, err=%v", decision.Allowed, err)
		}
	}
}

// BenchmarkOPA_Decide_Parallel 多协程高并发压测（模拟高吞吐生产网关）
func BenchmarkOPA_Decide_Parallel(b *testing.B) {
	authorizer, err := NewOPAAuthorizer(context.Background())
	if err != nil {
		b.Fatal(err)
	}

	policy := domain.Policy{
		Statement: []domain.Statement{{
			Effect:   domain.Allow,
			Action:   []string{"user:*"},
			Resource: []string{"*"},
		}},
	}

	input := AuthInput{
		Actions:    []string{"user:list"},
		Resource:   "urn:iam:api:user:GET:/api/v1/users",
		Policies:   []domain.Policy{policy},
		Attributes: map[pbac.AttributeKey]any{pbac.PrincipalUsername: "alice"},
	}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			decision, err := authorizer.Decide(ctx, input)
			if err != nil || !decision.Allowed {
				b.Fatalf("decide failed: allowed=%v, err=%v", decision.Allowed, err)
			}
		}
	})
}
