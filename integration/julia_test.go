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

func scanJulia(t *testing.T, input string, extra ...string) model.Document {
	t.Helper()
	args := append([]string{"scan", input, "--format", "ravel-json"}, extra...)
	out, err := exec.Command(executable, args...).Output()
	if err != nil {
		t.Fatalf("Julia scan %v: %v: %s", args, err, out)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestJuliaManifestFormats(t *testing.T) {
	v2 := scanJulia(t, filepath.Join("..", "testdata", "fixtures", "julia-v2"))
	if v2.Coverage.Manager != "julia" || v2.Coverage.Packages != 5 || v2.Coverage.Edges != 4 || v2.Coverage.GraphState != "partial" || v2.Coverage.OriginState != "partial" || len(v2.Sources) != 1 {
		t.Fatalf("Julia v2 coverage: %#v", v2.Coverage)
	}
	ids := map[string]string{}
	for _, pkg := range v2.Components {
		ids[pkg.ID] = pkg.Name + "@" + pkg.Version
		if pkg.PURL != "" || len(pkg.Evidence) != 1 || pkg.Evidence[0].InputDigest == "" {
			t.Fatalf("unverified Julia PURL or evidence: %#v", pkg)
		}
	}
	linked := map[string]bool{}
	for _, edge := range v2.Edges {
		from := ids[edge.From]
		if edge.From == "root" {
			from = "root"
		}
		linked[from+"->"+ids[edge.To]+":"+edge.Condition] = true
	}
	for _, want := range []string{
		"root->Alpha@1.2.3:",
		"Alpha@1.2.3->Shared@2.0.0:",
		"Alpha@1.2.3->Std@:",
		"Alpha@1.2.3->Optional@0.5.0:weak dependency",
	} {
		if !linked[want] {
			t.Fatalf("missing Julia edge %q: %#v", want, linked)
		}
	}
	encoded, err := json.Marshal(v2)
	if err != nil || strings.Contains(string(encoded), "secret") {
		t.Fatalf("Julia credential leaked: %v", err)
	}
	v1 := scanJulia(t, filepath.Join("..", "testdata", "fixtures", "julia-v1", "Manifest.toml"))
	if v1.Coverage.Packages != 3 || v1.Coverage.Edges != 2 || !dotnetIssue(v1, "missing_direct_dependencies") || !dotnetIssue(v1, "version_unresolved") {
		t.Fatalf("Julia v1 coverage: %#v", v1.Coverage)
	}
	alt := scanJulia(t, filepath.Join("..", "testdata", "fixtures", "julia-alternate"), "--manager", "julia")
	if alt.Coverage.Packages != 2 || alt.Coverage.Edges != 2 || len(alt.Sources) != 1 {
		t.Fatalf("Julia alternate coverage: %#v", alt.Coverage)
	}
	ambiguous := scanJulia(t, filepath.Join("..", "testdata", "fixtures", "julia-ambiguous"))
	if ambiguous.Coverage.Packages != 3 || ambiguous.Coverage.Edges != 0 || !dotnetIssue(ambiguous, "ambiguous_dependency") {
		t.Fatalf("Julia ambiguous name coverage: %#v", ambiguous.Coverage)
	}
	versioned := scanJulia(t, filepath.Join("..", "testdata", "fixtures", "julia-versioned"))
	if versioned.Coverage.Packages != 1 || versioned.Coverage.Edges != 1 || len(versioned.Sources) != 1 {
		t.Fatalf("Julia versioned coverage: %#v", versioned.Coverage)
	}
}

func TestJuliaManifestDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "julia-v2")
	root := t.TempDir()
	nested := filepath.Join(root, "julia")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Manifest.toml", "Project.toml"} {
		data, err := os.ReadFile(filepath.Join(fixture, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(nested, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{nested},
		{nested, "--manager", "julia"},
		{root, "--all", "--recursive"},
	} {
		doc := scanJulia(t, args[0], args[1:]...)
		if doc.Coverage.Packages != 5 {
			t.Fatalf("Julia discovery %v: %#v", args, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", fixture, "--format", format).Output()
		if err != nil || !json.Valid(out) || strings.Contains(string(out), "secret") {
			t.Fatalf("Julia %s export: %v %s", format, err, out)
		}
	}
	data, err := os.ReadFile(filepath.Join(fixture, "Manifest.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "JuliaManifest.toml"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", nested, "--manager", "julia"},
		{"scan", root, "--all", "--recursive"},
	} {
		out, err := exec.Command(executable, args...).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "multiple Julia manifests") {
			t.Fatalf("expected Julia manifest ambiguity for %v: %v %s", args, err, out)
		}
	}
}
