package npm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceIdentityRequiresMatchingLockedVersion(t *testing.T) {
	for _, manifest := range []string{
		`{"name":"frontend","version":"0.2.0"}`,
		`{"name":"frontend"}`,
		`{"version":"0.1.0"}`,
	} {
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, "frontend"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "frontend", "package.json"), []byte(manifest), 0600); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(root, "package-lock.json")
		if err := os.WriteFile(file, []byte(`{"lockfileVersion":3,"packages":{"":{},"frontend":{"version":"0.1.0"}}}`), 0600); err != nil {
			t.Fatal(err)
		}
		doc, err := Collect(file, "test")
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Components) != 0 {
			t.Fatal("unmatched manifest supplied a locked identity", doc.Components)
		}
		unresolved := false
		for _, issue := range doc.Coverage.Issues {
			if issue.Code == "unresolved_dependency" && issue.Name == "frontend" {
				unresolved = true
			}
		}
		if !unresolved {
			t.Fatal("missing workspace identity was not reported")
		}
	}
}
