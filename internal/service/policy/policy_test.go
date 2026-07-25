package policy

import (
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/pbac"
)

func TestValidatePolicyExpressionsSeparatesConditionAndAccessScope(t *testing.T) {
	valid := domain.Policy{Statement: []domain.Statement{{
		Condition: &pbac.Condition{Predicate: &pbac.Predicate{
			Key: pbac.PrincipalUsername, Operator: pbac.StringEquals, Values: []pbac.Operand{pbac.Literal("alice")},
		}},
		AccessScope: &pbac.AccessScope{Predicate: &pbac.Predicate{
			Key: "ticket:create_by", Operator: pbac.StringEquals, Values: []pbac.Operand{pbac.Ref(pbac.PrincipalUsername)},
		}},
	}}}
	if err := ValidatePolicyExpressions(valid); err != nil {
		t.Fatalf("expected separated policy to be valid: %v", err)
	}

	invalid := valid
	invalid.Statement = append([]domain.Statement(nil), valid.Statement...)
	invalid.Statement[0].Condition = invalid.Statement[0].AccessScope
	if err := ValidatePolicyExpressions(invalid); err == nil {
		t.Fatal("expected business AccessScope in Condition to be rejected")
	}
}
