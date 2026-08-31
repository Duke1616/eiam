package authz

import (
	"context"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/pbac"
)

func TestDecidePreservesOPAAndReturnsResidualAccessScope(t *testing.T) {
	authorizer := newTestAuthorizer(t)
	accessScope := &pbac.AccessScope{Predicate: &pbac.Predicate{
		Key:      "ticket:create_by",
		Operator: pbac.StringEquals,
		Values:   []pbac.Operand{pbac.Ref(pbac.PrincipalUsername)},
	}}
	policies := []domain.Policy{{Statement: []domain.Statement{{
		Effect:      domain.Allow,
		Action:      []string{"ticket:*"},
		Resource:    []string{"*"},
		AccessScope: accessScope,
	}}}}
	decision, err := authorizer.Decide(context.Background(), AuthInput{
		Actions:       []string{"ticket:history"},
		Resource:      "ticket:api:get:/history",
		Policies:      policies,
		Attributes:    map[pbac.AttributeKey]any{pbac.PrincipalUsername: "alice"},
		FilterProfile: "ticket_history.v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.AllowAccessScope == nil || decision.AllowAccessScope.Predicate.Values[0].Value != "alice" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestDecideSeparatesConditionAndAccessScope(t *testing.T) {
	authorizer := newTestAuthorizer(t)
	policy := domain.Policy{Statement: []domain.Statement{{
		Effect:   domain.Allow,
		Action:   []string{"ticket:history"},
		Resource: []string{"*"},
		Condition: &pbac.Condition{Predicate: &pbac.Predicate{
			Key: pbac.PrincipalUsername, Operator: pbac.StringEquals, Values: []pbac.Operand{pbac.Literal("alice")},
		}},
		AccessScope: &pbac.AccessScope{Predicate: &pbac.Predicate{
			Key: "ticket:create_by", Operator: pbac.StringEquals, Values: []pbac.Operand{pbac.Ref(pbac.PrincipalUsername)},
		}},
	}}}

	input := AuthInput{
		Actions:       []string{"ticket:history"},
		Resource:      "ticket:api:get:/history",
		Policies:      []domain.Policy{policy},
		Attributes:    map[pbac.AttributeKey]any{pbac.PrincipalUsername: "alice"},
		FilterProfile: "ticket_history.v1",
	}
	decision, err := authorizer.Decide(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.AllowAccessScope == nil || decision.AllowAccessScope.Predicate.Values[0].Value != "alice" {
		t.Fatalf("unexpected decision: %#v", decision)
	}

	input.Attributes[pbac.PrincipalUsername] = "bob"
	decision, err = authorizer.Decide(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatalf("Condition mismatch must deny before AccessScope evaluation: %#v", decision)
	}
}

func TestDecideUnconditionalPolicyUsesOriginalOPAPath(t *testing.T) {
	authorizer := newTestAuthorizer(t)
	policies := []domain.Policy{{Statement: []domain.Statement{{
		Effect:   domain.Allow,
		Action:   []string{"ticket:*"},
		Resource: []string{"*"},
	}}}}
	allowed, err := authorizer.Authorize(context.Background(), AuthInput{
		Actions:  []string{"ticket:history"},
		Resource: "ticket:api:get:/history",
		Policies: policies,
	})
	if err != nil || !allowed {
		t.Fatalf("expected original OPA path to allow, allowed=%v err=%v", allowed, err)
	}
}

func TestConditionalCoordinatorPreservesUnconditionalOPASemantics(t *testing.T) {
	authorizer := newTestAuthorizer(t).(*OPAAuthorizer)
	tests := []struct {
		name       string
		actions    []string
		resource   string
		statements []domain.Statement
		want       bool
	}{
		{
			name:     "exact action and resource",
			actions:  []string{"ticket:history"},
			resource: "ticket:api:get:/history",
			statements: []domain.Statement{{
				Effect: domain.Allow, Action: []string{"ticket:history"}, Resource: []string{"ticket:api:get:/history"},
			}},
			want: true,
		},
		{
			name:     "action and resource wildcard",
			actions:  []string{"ticket:history"},
			resource: "ticket:api:get:/history",
			statements: []domain.Statement{{
				Effect: domain.Allow, Action: []string{"ticket:*"}, Resource: []string{"*"},
			}},
			want: true,
		},
		{
			name:     "resource mismatch",
			actions:  []string{"ticket:history"},
			resource: "ticket:api:get:/history",
			statements: []domain.Statement{{
				Effect: domain.Allow, Action: []string{"ticket:history"}, Resource: []string{"ticket:api:get:/todo"},
			}},
		},
		{
			name:     "explicit deny overrides allow",
			actions:  []string{"ticket:history"},
			resource: "ticket:api:get:/history",
			statements: []domain.Statement{
				{Effect: domain.Allow, Action: []string{"ticket:*"}, Resource: []string{"*"}},
				{Effect: domain.Deny, Action: []string{"ticket:history"}, Resource: []string{"*"}},
			},
		},
		{
			name:     "deny matches one candidate action",
			actions:  []string{"ticket:history", "ticket:export"},
			resource: "ticket:api:get:/history",
			statements: []domain.Statement{
				{Effect: domain.Allow, Action: []string{"ticket:history"}, Resource: []string{"*"}},
				{Effect: domain.Deny, Action: []string{"ticket:export"}, Resource: []string{"*"}},
			},
		},
	}

	conditionMarker := domain.Statement{
		Effect:   domain.Allow,
		Action:   []string{"compatibility:marker"},
		Resource: []string{"*"},
		Condition: &pbac.Condition{Predicate: &pbac.Predicate{
			Key: pbac.PrincipalUsername, Operator: pbac.StringEquals, Values: []pbac.Operand{pbac.Literal("alice")},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statements := append([]domain.Statement{}, tt.statements...)
			statements = append(statements, conditionMarker)
			input := AuthInput{
				Actions: tt.actions, Resource: tt.resource, Policies: []domain.Policy{{Statement: statements}},
			}
			oldAllowed, err := authorizer.authorizeOPA(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := authorizer.Decide(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if oldAllowed != decision.Allowed || decision.Allowed != tt.want {
				t.Fatalf("old OPA=%v conditional coordinator=%v want=%v", oldAllowed, decision.Allowed, tt.want)
			}
		})
	}
}

func TestAuthorizeBatchWithUnrelatedConditionMatchesOriginalOPA(t *testing.T) {
	authorizer := newTestAuthorizer(t)
	basePolicy := domain.Policy{Statement: []domain.Statement{{
		Effect: domain.Allow, Action: []string{"ticket:history"}, Resource: []string{"*"},
	}}}
	input := AuthInput{
		BatchResources: []string{"history-menu", "todo-menu"},
		ResourceActions: map[string][]string{
			"history-menu": {"ticket:history"},
			"todo-menu":    {"ticket:todo"},
		},
		Policies: []domain.Policy{basePolicy},
	}
	original, err := authorizer.AuthorizeBatch(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}

	input.Policies = append(input.Policies, domain.Policy{Statement: []domain.Statement{{
		Effect: domain.Allow, Action: []string{"compatibility:marker"}, Resource: []string{"*"},
		Condition: &pbac.Condition{Predicate: &pbac.Predicate{
			Key: pbac.PrincipalUsername, Operator: pbac.StringEquals, Values: []pbac.Operand{pbac.Literal("alice")},
		}},
	}}})
	conditional, err := authorizer.AuthorizeBatch(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(original) != 1 || original[0] != "history-menu" ||
		len(conditional) != 1 || conditional[0] != "history-menu" {
		t.Fatalf("original=%v conditional=%v", original, conditional)
	}
}

func TestDecideReturnsConditionalDenyAsResidualAccessScope(t *testing.T) {
	authorizer := newTestAuthorizer(t)
	policies := []domain.Policy{{Statement: []domain.Statement{
		{
			Effect:   domain.Allow,
			Action:   []string{"ticket:history"},
			Resource: []string{"*"},
		},
		{
			Effect:   domain.Deny,
			Action:   []string{"ticket:history"},
			Resource: []string{"*"},
			AccessScope: &pbac.AccessScope{Predicate: &pbac.Predicate{
				Key:      "ticket:create_by",
				Operator: pbac.StringEquals,
				Values:   []pbac.Operand{pbac.Ref(pbac.PrincipalUsername)},
			}},
		},
	}}}

	decision, err := authorizer.Decide(context.Background(), AuthInput{
		Actions:       []string{"ticket:history"},
		Resource:      "ticket:api:get:/history",
		Policies:      policies,
		Attributes:    map[pbac.AttributeKey]any{pbac.PrincipalUsername: "alice"},
		FilterProfile: "ticket_history.v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.AllowAccessScope != nil || decision.DenyAccessScope == nil {
		t.Fatalf("unexpected conditional deny decision: %#v", decision)
	}
}

func TestDecideEvaluatesPrincipalAndTimeConditions(t *testing.T) {
	authorizer := newTestAuthorizer(t)
	policies := []domain.Policy{{Statement: []domain.Statement{{
		Effect:   domain.Allow,
		Action:   []string{"ticket:history"},
		Resource: []string{"*"},
		Condition: &pbac.Condition{All: []pbac.Condition{
			{Predicate: &pbac.Predicate{
				Key:      pbac.PrincipalUsername,
				Operator: pbac.StringEquals,
				Values:   []pbac.Operand{pbac.Literal("alice")},
			}},
			{Predicate: &pbac.Predicate{
				Key:      pbac.EnvironmentCurrentTime,
				Operator: pbac.DateLessThan,
				Values:   []pbac.Operand{pbac.Literal("2030-01-01T00:00:00Z")},
			}},
		}},
	}}}}

	decision, err := authorizer.Decide(context.Background(), AuthInput{
		Actions:  []string{"ticket:history"},
		Resource: "ticket:api:get:/history",
		Policies: policies,
		Attributes: map[pbac.AttributeKey]any{
			pbac.PrincipalUsername:      "alice",
			pbac.EnvironmentCurrentTime: "2029-01-01T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.AllowAccessScope != nil {
		t.Fatalf("expected immediate conditions to allow without an AccessScope: %#v", decision)
	}
}

func TestFastPathShortCircuit(t *testing.T) {
	authorizer := newTestAuthorizer(t)
	ctx := context.Background()

	// 1. 测试 Decide 无策略时的零开销短路
	decision, err := authorizer.Decide(ctx, AuthInput{
		Actions:  []string{"ticket:view"},
		Resource: "ticket:api:get:/view",
		Policies: nil,
	})
	if err != nil {
		t.Fatalf("unexpected error on nil policies: %v", err)
	}
	if decision.Allowed || decision.ReasonCode != pbac.ReasonNoMatchingAllow {
		t.Fatalf("expected implicit deny on empty policies, got %#v", decision)
	}

	// 2. 测试 Authorize 无策略时的零开销短路
	allowed, err := authorizer.Authorize(ctx, AuthInput{
		Actions:  []string{"ticket:view"},
		Resource: "ticket:api:get:/view",
		Policies: []domain.Policy{},
	})
	if err != nil {
		t.Fatalf("unexpected error on empty policies: %v", err)
	}
	if allowed {
		t.Fatalf("expected false on empty policies")
	}

	// 3. 测试 AuthorizeBatch 无资源或无策略时的短路
	batchAllowed, err := authorizer.AuthorizeBatch(ctx, AuthInput{
		BatchResources: []string{},
		Policies: []domain.Policy{{
			Statement: []domain.Statement{{Effect: domain.Allow, Action: []string{"*"}, Resource: []string{"*"}}},
		}},
	})
	if err != nil || len(batchAllowed) != 0 {
		t.Fatalf("expected empty result on empty batch resources, got %v, err=%v", batchAllowed, err)
	}

	batchAllowed, err = authorizer.AuthorizeBatch(ctx, AuthInput{
		BatchResources: []string{"res:1", "res:2"},
		Policies:       []domain.Policy{},
	})
	if err != nil || len(batchAllowed) != 0 {
		t.Fatalf("expected empty result on empty policies, got %v, err=%v", batchAllowed, err)
	}
}

func newTestAuthorizer(t *testing.T) IAuthorizer {
	t.Helper()
	authorizer, err := NewOPAAuthorizer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return authorizer
}
