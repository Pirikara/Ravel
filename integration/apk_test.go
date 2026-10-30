package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ravel/internal/model"
)

func apkFixture(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "testdata", "fixtures", name)
}

func scanAPK(t *testing.T, source string, args ...string) (model.Document, string, int) {
	t.Helper()
	result := filepath.Join(t.TempDir(), "apk.json")
	command := append([]string{"scan", source, "--format", "ravel-json", "--output", result}, args...)
	output, err := exec.Command(executable, command...).CombinedOutput()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return model.Document{}, string(output), exit.ExitCode()
		}
		t.Fatal(err)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, string(output), 0
}

func TestAPKInstalledDatabaseEvidenceAndGraph(t *testing.T) {
	fixture := apkFixture(t, "apk-basic")
	installed := filepath.Join(fixture, "lib", "apk", "db", "installed")
	doc, output, code := scanAPK(t, installed)
	if code != 0 || doc.Coverage.Manager != "apk" || doc.Coverage.Packages != 3 || doc.Coverage.Edges != 5 || doc.Coverage.GraphState != "complete_for_scope" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("APK scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
		if component.PURL != "" || component.Evidence[0].Collector != "apk-installed" || component.Evidence[0].InputDigest == "" || component.Evidence[0].Line == 0 {
			t.Fatalf("APK identity or evidence overstated: %#v", component)
		}
	}
	for _, name := range []string{"busybox", "musl", "sample-app"} {
		if ids[name] == "" {
			t.Fatalf("missing APK package %s: %#v", name, doc.Components)
		}
	}
	for _, name := range []string{"busybox", "musl"} {
		found := false
		for _, edge := range doc.Edges {
			found = found || edge.From == ids["sample-app"] && edge.To == ids[name] && edge.Condition == ""
		}
		if !found {
			t.Fatalf("missing APK dependency on %s: %#v", name, doc.Edges)
		}
	}
	if output, err := exec.Command(executable, "scan", installed, "--output", installed).CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("APK database overwrite accepted: %v: %s", err, output)
	}
	if dirDoc, output, code := scanAPK(t, fixture, "--manager", "apk"); code != 0 || dirDoc.Coverage.Packages != 3 {
		t.Fatalf("APK rootfs scan failed: code=%d output=%s", code, output)
	}
}

func TestAPKDependencyCases(t *testing.T) {
	for _, tc := range []struct {
		fixture, graph, issue string
		packages, edges       int
		conditional           int
	}{
		{"apk-virtual", "partial", "conditional_graph", 3, 5, 2},
		{"apk-versioned", "partial", "dependency_constraint_unverified", 2, 3, 0},
		{"apk-missing", "partial", "unresolved_dependency", 1, 1, 0},
		{"apk-broken", "partial", "apk_package_unhealthy", 1, 1, 0},
		{"apk-conflict", "complete_for_scope", "", 2, 3, 0},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			doc, output, code := scanAPK(t, apkFixture(t, tc.fixture))
			if code != 0 || doc.Coverage.Packages != tc.packages || doc.Coverage.Edges != tc.edges || doc.Coverage.GraphState != tc.graph {
				t.Fatalf("APK fixture mismatch: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
			}
			conditional := 0
			for _, edge := range doc.Edges {
				if edge.Condition != "" {
					conditional++
				}
			}
			if conditional != tc.conditional {
				t.Fatalf("APK conditional edges: got %d want %d", conditional, tc.conditional)
			}
			if tc.issue != "" {
				found := false
				for _, issue := range doc.Coverage.Issues {
					found = found || issue.Code == tc.issue
				}
				if !found {
					t.Fatalf("missing APK issue %s: %#v", tc.issue, doc.Coverage.Issues)
				}
			}
		})
	}
}

func TestAPKRecursiveAndInvalidDatabase(t *testing.T) {
	source := filepath.Join(apkFixture(t, "apk-basic"), "lib", "apk", "db", "installed")
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	installed := filepath.Join(base, "images", "rootfs", "lib", "apk", "db", "installed")
	if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, data, 0o644); err != nil {
		t.Fatal(err)
	}
	doc, output, code := scanAPK(t, base, "--all", "--recursive")
	if code != 0 || doc.Coverage.Packages != 3 || doc.Coverage.Edges != 5 {
		t.Fatalf("recursive APK scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	for _, bad := range [][]byte{[]byte("ADB\x00binary"), []byte("P:bad\nV:1\nA:x86_64\nP:duplicate\n")} {
		if err := os.WriteFile(installed, bad, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, output, code := scanAPK(t, installed); code != 1 || !strings.Contains(output, "ravel:") {
			t.Fatalf("invalid APK database accepted: code=%d output=%s", code, output)
		}
	}
}
