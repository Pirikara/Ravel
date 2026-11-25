package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestCompareRootIdentity(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after *model.ProjectIdentity
		text          string
	}{
		{"added", nil, &model.ProjectIdentity{Name: "app", Version: "1.0.0"}, "+ application app@1.0.0"},
		{"removed", &model.ProjectIdentity{Name: "app"}, nil, "- application app"},
		{"version", &model.ProjectIdentity{Name: "app", Version: "1.0.0"}, &model.ProjectIdentity{Name: "app", Version: "2.0.0"}, "~ application app@1.0.0 -> app@2.0.0"},
		{"name", &model.ProjectIdentity{Name: "old"}, &model.ProjectIdentity{Name: "new"}, "~ application old -> new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diff := Compare(model.Document{Root: tc.before}, model.Document{Root: tc.after})
			if diff.RootChange == nil || diff.RootChange.Before != tc.before || diff.RootChange.After != tc.after || !strings.Contains(DiffText(diff), tc.text) {
				t.Fatalf("root identity change lost: %+v\n%s", diff, DiffText(diff))
			}
		})
	}
	before := model.Document{Root: &model.ProjectIdentity{Name: "app", Version: "1.0.0", Evidence: model.Evidence{InputPath: "old/package.json", InputDigest: "old"}}}
	after := model.Document{Root: &model.ProjectIdentity{Name: "app", Version: "1.0.0", Evidence: model.Evidence{InputPath: "new/package.json", InputDigest: "new"}}}
	if diff := Compare(before, after); diff.RootChange != nil {
		t.Fatalf("evidence-only root change was reported: %+v", diff)
	}
}

func TestCompareRuntimeSemantics(t *testing.T) {
	base := model.RuntimeRequirement{Name: "node", Requirement: "22.0.0", Relation: "selection", Scope: "app"}
	for _, tc := range []struct {
		name   string
		change func(*model.RuntimeRequirement)
	}{
		{"name", func(r *model.RuntimeRequirement) { r.Name = "python" }},
		{"version", func(r *model.RuntimeRequirement) { r.Requirement = "24.0.0" }},
		{"relation", func(r *model.RuntimeRequirement) { r.Relation = "minimum" }},
		{"scope", func(r *model.RuntimeRequirement) { r.Scope = "other" }},
		{"policy", func(r *model.RuntimeRequirement) { r.Policy = "latestFeature" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := base
			tc.change(&next)
			diff := Compare(model.Document{Runtimes: []model.RuntimeRequirement{base}}, model.Document{Runtimes: []model.RuntimeRequirement{next}})
			if len(diff.AddedRuntimes) != 1 || diff.AddedRuntimes[0] != next || len(diff.RemovedRuntimes) != 1 || diff.RemovedRuntimes[0] != base {
				t.Fatalf("runtime semantic change lost: %+v", diff)
			}
			text := DiffText(diff)
			if !strings.Contains(text, "- runtime node selection \"22.0.0\" [app]") || !strings.Contains(text, "+ runtime "+runtimeLabel(next)) {
				t.Fatal(text)
			}
		})
	}
	withEvidence := base
	withEvidence.Evidence = model.Evidence{InputPath: "moved/.node-version", InputDigest: "new", Line: 4}
	diff := Compare(model.Document{Runtimes: []model.RuntimeRequirement{base, base}}, model.Document{Runtimes: []model.RuntimeRequirement{withEvidence}})
	if len(diff.AddedRuntimes)+len(diff.RemovedRuntimes) != 0 {
		t.Fatalf("duplicate declarations or evidence changes became semantic changes: %+v", diff)
	}
}

func TestCompareRuntimeOrderAndPresence(t *testing.T) {
	node := model.RuntimeRequirement{Name: "node", Relation: "selection", Requirement: "24", Scope: "app"}
	python := model.RuntimeRequirement{Name: "python", Relation: "minimum", Requirement: "3.13", Scope: "app"}
	a := model.Document{Runtimes: []model.RuntimeRequirement{node, python}}
	b := model.Document{Runtimes: []model.RuntimeRequirement{python, node}}
	first, _ := json.Marshal(Compare(model.Document{}, a))
	second, _ := json.Marshal(Compare(model.Document{}, b))
	if string(first) != string(second) {
		t.Fatalf("runtime diff is order-dependent:\n%s\n%s", first, second)
	}
	if diff := Compare(a, b); len(diff.AddedRuntimes)+len(diff.RemovedRuntimes) != 0 {
		t.Fatalf("reordered declarations became changes: %+v", diff)
	}
	if diff := Compare(a, model.Document{}); len(diff.RemovedRuntimes) != 2 || len(diff.AddedRuntimes) != 0 {
		t.Fatalf("runtime removals lost: %+v", diff)
	}
}

func TestCompareOriginVCSType(t *testing.T) {
	origin := model.Origin{Occurrence: "p", Kind: "vcs", SafeURL: "https://code.example.test/demo", VCSType: "git"}
	before := model.Document{Origins: []model.Origin{origin}}
	origin.VCSType = "hg"
	diff := Compare(before, model.Document{Origins: []model.Origin{origin}})
	if len(diff.AddedOrigins) != 1 || diff.AddedOrigins[0].VCSType != "hg" || len(diff.RemovedOrigins) != 1 || diff.RemovedOrigins[0].VCSType != "git" {
		t.Fatalf("VCS type change lost: %+v", diff)
	}
}
