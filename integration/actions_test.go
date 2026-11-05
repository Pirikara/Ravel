package integration_test

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestGitHubActionsWorkflowScan(t *testing.T) {
	root := filepath.Join("..", "testdata", "fixtures", "github-actions-basic")
	workflow := filepath.Join(root, ".github", "workflows", "ci.yml")
	for _, args := range [][]string{
		{"scan", workflow, "--format", "ravel-json"},
		{"scan", root, "--all", "--recursive", "--format", "ravel-json"},
	} {
		out, err := exec.Command(executable, args...).Output()
		if err != nil {
			t.Fatalf("scan %q: %v", args, err)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Components) != 3 || len(doc.Edges) != 3 || doc.Coverage.GraphState != "partial" || doc.Coverage.Manager != "github-actions" {
			t.Fatalf("workflow action references lost: %#v", doc.Coverage)
		}
		found := map[string]bool{}
		for _, component := range doc.Components {
			found[component.Name+"@"+component.Version] = true
			if component.PURL == "" || len(component.Evidence) == 0 || component.Evidence[0].Line == 0 {
				t.Fatalf("workflow action identity or evidence missing: %#v", component)
			}
		}
		for _, want := range []string{"actions/checkout@v6", "actions/cache/save@v5", "owner/repository/.github/workflows/reuse.yml@v2"} {
			if !found[want] {
				t.Fatalf("missing workflow use %s", want)
			}
		}
	}
}
