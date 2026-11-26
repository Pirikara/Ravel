package report

import (
	"github.com/Pirikara/Ravel/internal/model"
	"testing"
)

func TestLicenseDiffTracksDeclarationsAndIgnoresEvidence(t *testing.T) {
	makeDoc := func(value, path string) model.Document {
		licenses := []model.LicenseDeclaration{{Kind: "license", Value: value, Evidence: []model.Evidence{{InputPath: path}}}}
		return model.Document{Root: &model.ProjectIdentity{Name: "app", Licenses: licenses}, Components: []model.Component{{ID: "pkg", Name: "pkg", Version: "1", Licenses: licenses}}}
	}
	a, b := makeDoc("MIT", "a"), makeDoc("MIT", "b")
	if d := Compare(a, b); d.RootChange != nil || len(d.ChangedComponents) != 0 {
		t.Fatalf("evidence-only change: %+v", d)
	}
	b = makeDoc("Apache-2.0", "b")
	if d := Compare(a, b); d.RootChange == nil || len(d.ChangedComponents) != 1 {
		t.Fatalf("license change lost: %+v", d)
	}
	if a.Components[0].Licenses[0].Evidence[0].InputPath != "a" {
		t.Fatal("diff mutated input")
	}
}
