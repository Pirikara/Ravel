package report

import (
	"github.com/Pirikara/Ravel/internal/model"
	"testing"
)

func TestDevelopmentDirectoryDiffAndEvidence(t *testing.T) {
	source := model.Development{Occurrence: "pkg", SafeURL: "https://code.example.test/repo", Status: "declared", Directory: "packages/a", Evidence: model.Evidence{InputPath: "old"}}
	next := source
	next.Evidence.InputPath = "new"
	a := model.Document{Development: []model.Development{source}}
	b := model.Document{Development: []model.Development{next}}
	if diff := Compare(a, b); len(diff.AddedDevelopment)+len(diff.RemovedDevelopment) != 0 {
		t.Fatal(diff)
	}
	next.Directory = "packages/b"
	b.Development[0] = next
	if diff := Compare(a, b); len(diff.AddedDevelopment) != 1 || len(diff.RemovedDevelopment) != 1 {
		t.Fatal(diff)
	}
}
