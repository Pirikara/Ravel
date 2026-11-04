package vex

import (
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestCorrelatePreservesOccurrencesAndRequiresExactPURL(t *testing.T) {
	sbom := model.Document{Components: []model.Component{
		{ID: "one", PURL: "pkg:npm/alpha@1.0.0"},
		{ID: "two", PURL: "pkg:npm/alpha@1.0.0"},
		{ID: "three", PURL: "pkg:npm/alpha@2.0.0"},
	}}
	data := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1","author":"Supplier","timestamp":"2026-10-01T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-1"},"products":[{"@id":"pkg:npm/alpha@1.0.0"},{"@id":"pkg:npm/alpha@1.0.1"},{"@id":"https://example.test/product/alpha","identifiers":{"cpe23":"cpe:2.3:a:example:alpha:1.0.0:*:*:*:*:*:*:*"}}],"status":"fixed"}]}`)
	result, err := Correlate(sbom, data)
	if err != nil {
		t.Fatal(err)
	}
	products := result.Statements[0].Products
	if !products[0].Matched || len(products[0].ComponentIDs) != 2 || products[0].ComponentIDs[0] != "one" || products[0].ComponentIDs[1] != "two" {
		t.Fatalf("occurrences lost: %+v", products[0])
	}
	if products[1].Matched || products[1].Reason != "purl_not_in_sbom" || products[2].Matched || products[2].Reason != "no_purl" {
		t.Fatalf("unexpected fuzzy match: %+v", products)
	}
}

func TestCorrelateRejectsAmbiguousOrIncompleteStatements(t *testing.T) {
	base := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1","author":"Supplier","timestamp":"2026-10-01T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-1"},"products":[{"@id":"pkg:npm/alpha@1.0.0"}],"status":"fixed"}]}`
	cases := []struct{ old, replacement, message string }{
		{`"status":"fixed"`, `"status":"not_affected"`, "requires justification"},
		{`"status":"fixed"`, `"status":"affected"`, "requires action_statement"},
		{`"status":"fixed"`, `"status":"unknown"`, "unsupported status"},
		{`"@id":"pkg:npm/alpha@1.0.0"`, `"@id":"pkg:npm/alpha@1.0.0","identifiers":{"purl":"pkg:npm/beta@1.0.0"}`, "conflicting"},
		{`"timestamp":"2026-10-01T12:00:00Z"`, `"timestamp":"yesterday"`, "timestamp"},
	}
	for _, tc := range cases {
		_, err := Correlate(model.Document{}, []byte(strings.Replace(base, tc.old, tc.replacement, 1)))
		if err == nil || !strings.Contains(err.Error(), tc.message) {
			t.Errorf("replacement %s: expected %q, got %v", tc.replacement, tc.message, err)
		}
	}
}
