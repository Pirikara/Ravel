package integration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestMavenModuleTraversalStaysInProject(t *testing.T) {
	base := t.TempDir()
	project := filepath.Join(base, "project")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	outsidePOM := `<project><groupId>org.example</groupId><artifactId>outside</artifactId><version>1</version><dependencies><dependency><groupId>org.example</groupId><artifactId>hidden</artifactId><version>1</version></dependency></dependencies></project>`
	if err := os.WriteFile(filepath.Join(outside, "pom.xml"), []byte(outsidePOM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(project, "linked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	rootPOM := `<project><groupId>org.example</groupId><artifactId>root</artifactId><version>1</version><modules><module>../outside</module><module>linked</module></modules></project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(rootPOM), 0o644); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(t.TempDir(), "ravel.json")
	if output, code := mavenScan(t, project, "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("Maven scan failed, code=%d output=%s", code, output)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 0 || len(doc.Edges) != 0 || len(doc.Sources) != 0 {
		t.Fatalf("Maven module traversal read outside project: %+v", doc)
	}
	unresolved := 0
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "maven_module_unresolved" {
			unresolved++
		}
	}
	if unresolved != 2 {
		t.Fatalf("rejected modules were not reported: %+v", doc.Coverage.Issues)
	}
}
