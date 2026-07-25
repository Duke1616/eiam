package gormx

import (
	"reflect"
	"testing"

	"github.com/Duke1616/eiam/pkg/pbac"
)

func TestCompileRequiresMatchingProfileAndBindsValues(t *testing.T) {
	profile := Profile{Name: "rows", CompilePredicate: func(predicate *pbac.Predicate) (Expression, error) {
		values, err := LiteralStrings(predicate.Values)
		if err != nil {
			return Expression{}, err
		}
		return Expression{SQL: "rows.owner IN (" + Placeholders(len(values)) + ")", Args: values}, nil
	}}
	decision := pbac.Decision{Allowed: true, FilterProfile: "rows", AllowAccessScope: &pbac.AccessScope{Predicate: &pbac.Predicate{Key: "row:owner", Operator: pbac.StringEquals, Values: []pbac.Operand{pbac.Literal("alice")}}}}
	expression, err := Compile(decision, profile)
	if err != nil {
		t.Fatal(err)
	}
	if expression.SQL != "(rows.owner IN (?))" || !reflect.DeepEqual(expression.Args, []any{"alice"}) {
		t.Fatalf("unexpected expression: %#v", expression)
	}
	decision.FilterProfile = "other"
	if _, err = Compile(decision, profile); err == nil {
		t.Fatal("expected profile mismatch")
	}
}
