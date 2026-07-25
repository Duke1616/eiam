package domain

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Duke1616/eiam/pkg/pbac"
)

func TestLegacyUnconditionalStatementJSONRemainsCompatible(t *testing.T) {
	type legacyCondition struct {
		Operator string `json:"Operator"`
		Key      string `json:"Key"`
		Value    any    `json:"Value"`
	}
	type legacyStatement struct {
		Effect    Effect            `json:"Effect"`
		Action    []string          `json:"Action"`
		Resource  []string          `json:"Resource"`
		Condition []legacyCondition `json:"Condition,omitempty"`
	}

	data, err := json.Marshal([]legacyStatement{{
		Effect: Allow, Action: []string{"ticket:history"}, Resource: []string{"*"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"Condition"`)) {
		t.Fatalf("legacy empty Condition must be omitted, got %s", data)
	}

	var statements []Statement
	if err = json.Unmarshal(data, &statements); err != nil {
		t.Fatal(err)
	}
	if len(statements) != 1 || statements[0].Condition != nil || statements[0].AccessScope != nil || statements[0].Effect != Allow {
		t.Fatalf("unexpected statements: %#v", statements)
	}
}

func TestStatementAccessScopeJSONRoundTrip(t *testing.T) {
	statement := Statement{
		Effect:   Allow,
		Action:   []string{"ticket:history"},
		Resource: []string{"*"},
		AccessScope: &AccessScope{Predicate: &pbac.Predicate{
			Key:      "ticket:create_by",
			Operator: pbac.StringEquals,
			Values:   []pbac.Operand{pbac.Ref(pbac.PrincipalUsername)},
		}},
	}
	data, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Statement
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.AccessScope == nil || decoded.AccessScope.Predicate == nil || decoded.Condition != nil {
		t.Fatalf("unexpected decoded statement: %#v", decoded)
	}
}
