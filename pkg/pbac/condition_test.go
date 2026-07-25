package pbac

import "testing"

func TestPartialEvaluateAccessScopeResolvesReference(t *testing.T) {
	scope := &AccessScope{Predicate: &Predicate{
		Key:      "ticket:create_by",
		Operator: StringEquals,
		Values:   []Operand{Ref(PrincipalUsername)},
	}}
	result, err := PartialEvaluateAccessScope(scope, map[AttributeKey]any{PrincipalUsername: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Residual() == nil || result.Residual().Predicate == nil {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Residual().Predicate.Values[0].Value != "alice" {
		t.Fatalf("reference was not resolved: %#v", result.Residual())
	}
}

func TestConditionAndAccessScopeUseSeparateAttributeNamespaces(t *testing.T) {
	businessCondition := &Condition{Predicate: &Predicate{
		Key: "ticket:create_by", Operator: StringEquals, Values: []Operand{Literal("alice")},
	}}
	if ValidateCondition(businessCondition) == nil {
		t.Fatal("expected business attribute in Condition to be rejected")
	}

	immediateScope := &AccessScope{Predicate: &Predicate{
		Key: PrincipalUsername, Operator: StringEquals, Values: []Operand{Literal("alice")},
	}}
	if ValidateAccessScope(immediateScope) == nil {
		t.Fatal("expected EIAM attribute in AccessScope to be rejected")
	}

	removedRequestScope := &AccessScope{Predicate: &Predicate{
		Key: "request:source_ip", Operator: IpAddress, Values: []Operand{Literal("10.0.0.0/8")},
	}}
	if ValidateAccessScope(removedRequestScope) == nil {
		t.Fatal("expected reserved EIAM namespace in AccessScope to be rejected")
	}
}

func TestEvaluateConditionDoesNotProduceResidual(t *testing.T) {
	condition := &Condition{Predicate: &Predicate{
		Key: PrincipalUsername, Operator: StringEquals, Values: []Operand{Literal("alice")},
	}}
	matched, err := EvaluateCondition(condition, map[AttributeKey]any{PrincipalUsername: "alice"})
	if err != nil || !matched {
		t.Fatalf("expected Condition to match, matched=%v err=%v", matched, err)
	}
}

func TestValidateConditionRejectsUnsupportedContextAttributes(t *testing.T) {
	keys := []AttributeKey{
		"principal:user_id",
		"principal:tenant_id",
		"auth:mfa_present",
		"request:source_ip",
		"request:method",
		"request:path",
		"request:secure_transport",
	}
	for _, key := range keys {
		t.Run(string(key), func(t *testing.T) {
			condition := &Condition{Predicate: &Predicate{
				Key: key, Operator: StringEquals, Values: []Operand{Literal("value")},
			}}
			if ValidateCondition(condition) == nil {
				t.Fatalf("expected unsupported Condition attribute %q to be rejected", key)
			}
		})
	}
}

func TestIPAddressOperator(t *testing.T) {
	matched, err := compare("10.1.2.3", IpAddress, []Operand{Literal("10.0.0.0/8")})
	if err != nil || !matched {
		t.Fatalf("expected address to match CIDR, matched=%v err=%v", matched, err)
	}
}

func TestCollectionOperators(t *testing.T) {
	tests := []struct {
		operator Operator
		expected string
		want     bool
	}{
		{ForAnyValueStringEquals, "bob", true},
		{ForAllValuesStringNotEquals, "carol", true},
		{ForAllValuesStringNotEquals, "bob", false},
	}
	for _, tt := range tests {
		got, err := compare([]string{"alice", "bob"}, tt.operator, []Operand{Literal(tt.expected)})
		if err != nil || got != tt.want {
			t.Fatalf("operator=%s got=%v err=%v", tt.operator, got, err)
		}
	}
}

func TestValidateRejectsMixedNode(t *testing.T) {
	condition := &Condition{Any: []Condition{{Predicate: &Predicate{Key: "x:y", Operator: Bool, Values: []Operand{Literal(true)}}}}, Predicate: &Predicate{}}
	if Validate(condition) == nil {
		t.Fatal("expected validation error")
	}
}
