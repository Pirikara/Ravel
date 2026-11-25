package merge

import (
	"testing"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/report"
)

func scopedInput(scope string) model.Document {
	doc := common.NewDocument(scope+"/package-lock.json", "app-"+scope, "npm", nil)
	doc.Root = &model.ProjectIdentity{Name: "app-" + scope, Version: "1.0.0"}
	doc.Components = []model.Component{
		{ID: "p", Kind: "package", Name: "shared", Version: "1.0.0", PURL: "pkg:npm/shared@1.0.0"},
		{ID: "q", Kind: "package", Name: "child", Version: "2.0.0", PURL: "pkg:npm/child@2.0.0"},
	}
	doc.Edges = []model.Edge{{From: "root", To: "p", Kind: "direct"}, {From: "p", To: "q", Kind: "depends_on", Condition: "platform=linux"}}
	doc.Origins = []model.Origin{{Occurrence: "p", Kind: "declared_registry", SafeURL: "https://registry.example.test", Status: "declared"}}
	doc.Development = []model.Development{{Occurrence: "p", SafeURL: "https://code.example.test/shared", Status: "declared"}}
	doc.Runtimes = []model.RuntimeRequirement{{Name: "node", Relation: "selection", Requirement: "24", Scope: scope}}
	common.Finalize(&doc)
	return doc
}

func mergedInput(t *testing.T, inputs ...model.Document) model.Document {
	t.Helper()
	doc, err := Documents("test", inputs)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{"root": true}
	for _, c := range doc.Components {
		if ids[c.ID] {
			t.Fatalf("duplicate component ID: %s", c.ID)
		}
		ids[c.ID] = true
	}
	for _, edge := range doc.Edges {
		if !ids[edge.From] || !ids[edge.To] {
			t.Fatalf("dangling edge: %+v", edge)
		}
	}
	for _, origin := range doc.Origins {
		if !ids[origin.Occurrence] {
			t.Fatalf("dangling origin: %+v", origin)
		}
	}
	return doc
}

func TestMergeOccurrencesSurviveAddedAndReorderedInputs(t *testing.T) {
	a, b, c := scopedInput("a"), scopedInput("b"), scopedInput("c")
	before := mergedInput(t, b, c)
	for _, inputs := range [][]model.Document{{a, b, c}, {b, a, c}, {c, b, a}} {
		after := mergedInput(t, inputs...)
		diff := report.Compare(before, after)
		if len(diff.AddedComponents) != 3 || len(diff.RemovedComponents)+len(diff.ChangedComponents) != 0 || len(diff.AddedEdges) != 3 || len(diff.RemovedEdges) != 0 || len(diff.AddedOrigins) != 1 || len(diff.RemovedOrigins) != 0 || len(diff.AddedDevelopment) != 1 || len(diff.RemovedDevelopment) != 0 || len(diff.AddedRuntimes) != 1 || len(diff.RemovedRuntimes) != 0 {
			t.Fatalf("new input changed existing occurrences: %+v", diff)
		}
		reverse := report.Compare(after, before)
		if len(reverse.RemovedComponents) != 3 || len(reverse.AddedComponents)+len(reverse.ChangedComponents) != 0 || len(reverse.RemovedEdges) != 3 || len(reverse.AddedEdges) != 0 {
			t.Fatalf("removed input changed remaining occurrences: %+v", reverse)
		}
	}
	reordered := report.Compare(before, mergedInput(t, c, b))
	if len(reordered.AddedComponents)+len(reordered.RemovedComponents)+len(reordered.ChangedComponents)+len(reordered.AddedEdges)+len(reordered.RemovedEdges)+len(reordered.AddedOrigins)+len(reordered.RemovedOrigins)+len(reordered.AddedDevelopment)+len(reordered.RemovedDevelopment) != 0 {
		t.Fatalf("reordering changed occurrences: %+v", reordered)
	}
}

func TestMergeStableNestedInputs(t *testing.T) {
	a, b, c, d := scopedInput("a"), scopedInput("b"), scopedInput("c"), scopedInput("d")
	before := mergedInput(t, mergedInput(t, b, c), d)
	after := mergedInput(t, mergedInput(t, a, b, c), d)
	diff := report.Compare(before, after)
	if len(diff.AddedComponents) != 3 || len(diff.RemovedComponents)+len(diff.ChangedComponents)+len(diff.RemovedEdges)+len(diff.RemovedOrigins)+len(diff.RemovedDevelopment) != 0 {
		t.Fatalf("adding a nested input changed existing occurrences: %+v", diff)
	}
}

func TestMergeKeepsDistinctScopesAtSameSource(t *testing.T) {
	a := scopedInput("same")
	b := scopedInput("same")
	b.Project = "different project"
	c := scopedInput("same")
	c.Coverage.Manager = "different-manager"
	doc := mergedInput(t, a, b, c)
	if len(doc.Components) != 9 {
		t.Fatalf("distinct scopes were combined: %+v", doc.Components)
	}
}

func TestMergeRejectsAmbiguousLegacyOccurrenceIDs(t *testing.T) {
	a, b := scopedInput("a"), scopedInput("b")
	for _, doc := range []*model.Document{&a, &b} {
		doc.Coverage.Inputs = []model.InputCoverage{{Manager: doc.Coverage.Manager, Project: doc.Project, Source: doc.Source}}
		doc.Coverage.Manager, doc.Project, doc.Source = "multi", "merged", "merged"
		doc.Root = nil
		doc.Edges = nil
	}
	// Earlier independent merges could emit the same occurrence IDs while
	// recording different leaf scopes. Do not publish ambiguous references.
	if _, err := Documents("outer", []model.Document{a, b}); err == nil {
		t.Fatal("ambiguous legacy IDs produced a merged SBOM")
	}
}
