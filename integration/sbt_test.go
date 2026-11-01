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

func scanSBT(t *testing.T, input string, extra ...string) model.Document {
	t.Helper()
	args := append([]string{"scan", input, "--format", "ravel-json"}, extra...)
	out, err := exec.Command(executable, args...).Output()
	if err != nil {
		t.Fatalf("sbt scan %v: %v", args, err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestSBTLockCLI(t *testing.T) {
	base := filepath.Join("..", "testdata", "fixtures")
	basic := scanSBT(t, filepath.Join(base, "sbt-basic"))
	if basic.Coverage.Manager != "sbt" || basic.Coverage.Packages != 3 || basic.Coverage.Edges != 0 || basic.Coverage.GraphState != "partial" || basic.Coverage.OriginState != "partial" || !dotnetIssue(basic, "sbt_artifact_hash_unverified") {
		t.Fatalf("sbt coverage: %#v", basic.Coverage)
	}
	for _, pkg := range basic.Components {
		if !strings.HasPrefix(pkg.PURL, "pkg:maven/org.example/") || len(pkg.Evidence) != 1 || pkg.Evidence[0].InputDigest == "" {
			t.Fatalf("sbt identity/evidence: %#v", pkg)
		}
		switch pkg.Name {
		case "org.example:core_2.13":
			if pkg.Context != "configurations=compile,runtime" || len(pkg.Hashes) != 1 || pkg.Hashes[0].Alg != "SHA-1" {
				t.Fatalf("sbt default JAR checksum: %#v", pkg)
			}
		case "org.example:testkit_2.13":
			if pkg.Context != "configurations=test" || len(pkg.Hashes) != 1 {
				t.Fatalf("sbt test configuration: %#v", pkg)
			}
		case "org.example:plugin":
			if len(pkg.Hashes) != 0 {
				t.Fatalf("sbt ambiguous artifacts: %#v", pkg)
			}
		default:
			t.Fatalf("unexpected sbt package: %#v", pkg)
		}
	}
	variants := scanSBT(t, filepath.Join(base, "sbt-variants"))
	if variants.Coverage.Packages != 2 || variants.Coverage.Edges != 0 || variants.Components[0].Version == variants.Components[1].Version {
		t.Fatalf("sbt variant selection: %#v", variants.Components)
	}
	partial := scanSBT(t, filepath.Join(base, "sbt-partial"))
	if partial.Coverage.Packages != 1 || !dotnetIssue(partial, "sbt_dependency_invalid") || !dotnetIssue(partial, "sbt_artifact_hash_unverified") {
		t.Fatalf("sbt partial coverage: %#v", partial.Coverage)
	}
}

func TestSBTDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "sbt-basic", "build.sbt.lock")
	root := t.TempDir()
	nested := filepath.Join(root, "scala")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "build.sbt.lock"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{nested},
		{nested, "--manager", "sbt"},
		{root, "--all", "--recursive"},
	} {
		doc := scanSBT(t, args[0], args[1:]...)
		if doc.Coverage.Packages != 3 {
			t.Fatalf("sbt discovery %v: %#v", args, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", fixture, "--format", format).Output()
		if err != nil || !json.Valid(out) {
			t.Fatalf("sbt %s export: %v", format, err)
		}
	}
	if err := os.WriteFile(filepath.Join(nested, "other.sbt.lock"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", nested, "--manager", "sbt"},
		{"scan", root, "--all", "--recursive"},
	} {
		out, err := exec.Command(executable, args...).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "multiple sbt lockfiles") {
			t.Fatalf("expected sbt ambiguity for %v: %v %s", args, err, out)
		}
	}
}
