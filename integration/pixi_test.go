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

func scanPixi(t *testing.T, input string, extra ...string) model.Document {
	t.Helper()
	args := append([]string{"scan", input, "--format", "ravel-json"}, extra...)
	out, err := exec.Command(executable, args...).Output()
	if err != nil {
		t.Fatalf("pixi scan %v: %v", args, err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestPixiSelectedOccurrencesAndEdges(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "pixi-v7")
	doc := scanPixi(t, fixture)
	if doc.Coverage.Manager != "pixi" || doc.Coverage.Packages != 9 || doc.Coverage.Edges != 12 || len(doc.Coverage.Platforms) != 2 || len(doc.Origins) != 9 || len(doc.Sources) != 1 {
		t.Fatalf("pixi v7 coverage: %#v", doc.Coverage)
	}
	ids := map[string]model.Component{}
	seen := map[string]bool{}
	for _, pkg := range doc.Components {
		key := pkg.Context + "/" + pkg.Platform + "/" + pkg.Name
		if seen[key] {
			t.Fatalf("duplicate occurrence: %s", key)
		}
		seen[key] = true
		ids[pkg.ID] = pkg
		if len(pkg.Evidence) != 2 || pkg.Evidence[0].InputDigest == "" || pkg.Evidence[1].Pointer == "" {
			t.Fatalf("missing selection or package evidence: %#v", pkg)
		}
		if pkg.Name == "PyParsing" && pkg.PURL != "pkg:pypi/pyparsing@3.2.0" {
			t.Fatalf("official PyPI identity: %#v", pkg)
		}
		if pkg.Name == "zlib" && pkg.PURL != "" {
			t.Fatalf("unverified Conda PURL: %#v", pkg)
		}
	}
	direct := 0
	for _, edge := range doc.Edges {
		if edge.Kind == "direct" {
			direct++
			if edge.From != "root" || edge.Evidence.Collector != "pixi-manifest" || !strings.Contains(edge.Condition, "environment=") || !strings.Contains(edge.Condition, "platform=") {
				t.Fatalf("invalid Pixi direct edge: %#v", edge)
			}
			if selected := ids[edge.To]; !strings.HasPrefix(edge.Condition, strings.Split(selected.Context, ";")[0]+"; platform="+selected.Platform) {
				t.Fatalf("Pixi direct edge crosses environment or platform: %#v -> %#v", edge, selected)
			}
			if strings.Contains(edge.Condition, "environment=docs") && ids[edge.To].Name != "zlib" && ids[edge.To].Name != "mike" {
				t.Fatalf("default feature leaked into docs: %#v", edge)
			}
			continue
		}
		from, to := ids[edge.From], ids[edge.To]
		if from.ID == "" || to.ID == "" || from.Platform != to.Platform || strings.Split(from.Context, ";")[0] != strings.Split(to.Context, ";")[0] || edge.Condition == "" {
			t.Fatalf("cross-scope or unconditional Pixi edge: %#v -> %#v", from, to)
		}
	}
	if direct != 9 || dotnetIssue(doc, "missing_direct_dependencies") || !dotnetIssue(doc, "pixi_virtual_requirement_unresolved") || !dotnetIssue(doc, "unresolved_dependency") {
		t.Fatalf("missing conservative Pixi gaps: %#v", doc.Coverage.Issues)
	}
	gitOrigins := 0
	for _, origin := range doc.Origins {
		if origin.Kind == "vcs" {
			gitOrigins++
			if origin.SafeURL != "https://github.com/example/mike" || origin.Revision != "2d4ad799442f4592db8ad53b179bfb33db8c69ac" {
				t.Fatalf("Git origin: %#v", origin)
			}
		}
	}
	if gitOrigins != 2 {
		t.Fatalf("Git occurrence count: %d", gitOrigins)
	}
}

func TestPixiV6AndPartial(t *testing.T) {
	base := filepath.Join("..", "testdata", "fixtures")
	v6 := scanPixi(t, filepath.Join(base, "pixi-v6", "pixi.lock"))
	if v6.Coverage.Packages != 2 || v6.Coverage.Edges != 1 || !strings.Contains(v6.Components[0].Context, "artifact-subdir=") || !dotnetIssue(v6, "missing_direct_dependencies") {
		t.Fatalf("pixi v6 coverage: %#v", v6.Coverage)
	}
	partial := scanPixi(t, filepath.Join(base, "pixi-partial"))
	if partial.Coverage.Packages != 1 || partial.Coverage.Edges != 0 || !dotnetIssue(partial, "pixi_hash_invalid") || !dotnetIssue(partial, "pixi_selected_package_unresolved") {
		t.Fatalf("pixi partial coverage: %#v", partial.Coverage)
	}
	encoded, err := json.Marshal(partial)
	if err != nil || strings.Contains(string(encoded), "hidden") || strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "?token=") {
		t.Fatalf("Pixi URL secret leaked: %v", err)
	}
}

func TestPixiFeaturePlatformSelection(t *testing.T) {
	root := t.TempDir()
	lock, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", "pixi-v7", "pixi.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pixi.lock"), lock, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `[dependencies]
python = "*"

[feature.linux-only]
platforms = ["linux-64"]

[feature.linux-only.pypi-dependencies]
mike = "*"

[environments]
default = ["linux-only"]
docs = { features = ["linux-only"], no-default-feature = true }
`
	if err := os.WriteFile(filepath.Join(root, "pixi.toml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := scanPixi(t, root)
	if doc.Coverage.Packages != 9 || doc.Coverage.Edges != 7 || dotnetIssue(doc, "missing_direct_dependencies") {
		t.Fatalf("Pixi feature platform coverage: %#v", doc.Coverage)
	}
	byID := map[string]model.Component{}
	for _, pkg := range doc.Components {
		byID[pkg.ID] = pkg
	}
	direct := map[string]bool{}
	for _, edge := range doc.Edges {
		if edge.Kind != "direct" {
			continue
		}
		pkg := byID[edge.To]
		key := strings.Split(pkg.Context, ";")[0] + "/" + pkg.Platform + "/" + pkg.Name
		direct[key] = true
	}
	for _, key := range []string{"environment=default/linux-64/python", "environment=default/osx-arm64/python", "environment=default/linux-64/mike", "environment=docs/linux-64/mike"} {
		if !direct[key] {
			t.Fatalf("missing Pixi direct requirement %s: %#v", key, direct)
		}
	}
	if len(direct) != 4 {
		t.Fatalf("feature platform or default inheritance leaked: %#v", direct)
	}
}

func TestPixiPyprojectNativeDependencies(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "pixi-pyproject")
	doc := scanPixi(t, fixture)
	if doc.Coverage.Manager != "pixi" || doc.Coverage.Packages != 19 || doc.Coverage.Edges != 19 || len(doc.Sources) != 1 || filepath.Base(doc.Sources[0]) != "pyproject.toml" {
		t.Fatalf("Pixi pyproject coverage: %#v", doc.Coverage)
	}
	if !dotnetIssue(doc, "pixi_manifest_marker_unverified") || dotnetIssue(doc, "unresolved_dependency") || dotnetIssue(doc, "pixi_manifest_group_unresolved") {
		t.Fatalf("Pixi native dependency gaps: %#v", doc.Coverage.Issues)
	}
	byID := map[string]model.Component{}
	for _, pkg := range doc.Components {
		byID[pkg.ID] = pkg
	}
	direct := map[string]model.Edge{}
	for _, edge := range doc.Edges {
		if edge.Kind != "direct" || edge.From != "root" || edge.Evidence.Collector != "pixi-manifest" {
			t.Fatalf("unexpected Pixi pyproject edge: %#v", edge)
		}
		pkg := byID[edge.To]
		key := strings.Split(pkg.Context, ";")[0] + "/" + pkg.Platform + "/" + pkg.Name
		direct[key] = edge
	}
	for _, key := range []string{
		"environment=default/linux-64/python", "environment=default/linux-64/packaging", "environment=default/linux-64/alpha",
		"environment=default/osx-arm64/python", "environment=default/osx-arm64/packaging",
		"environment=docs/linux-64/sphinx", "environment=dev/linux-64/pytest", "environment=dev/linux-64/ruff",
		"environment=dev/osx-arm64/pytest", "environment=dev/linux-64/sample", "environment=dev/osx-arm64/sample", "environment=all/linux-64/sphinx", "environment=all/linux-64/beta",
	} {
		if _, found := direct[key]; !found {
			t.Fatalf("missing Pixi native root %s", key)
		}
	}
	if len(direct) != 19 || direct["environment=default/osx-arm64/alpha"].To != "" {
		t.Fatalf("marker or override leaked a Pixi root: %#v", direct)
	}
	if edge := direct["environment=default/linux-64/alpha"]; !strings.Contains(edge.Condition, "marker unverified") {
		t.Fatalf("PEP 508 marker was asserted: %#v", edge)
	}
	if edge := direct["environment=all/linux-64/sphinx"]; !strings.Contains(edge.Condition, "marker unverified") {
		t.Fatalf("self-extra marker was asserted: %#v", edge)
	}
	for _, pkg := range doc.Components {
		if pkg.Name == "packaging" && pkg.PURL != "" {
			t.Fatalf("PyPI dependency overrode selected Conda package: %#v", pkg)
		}
	}
	local := 0
	for _, origin := range doc.Origins {
		if origin.Kind == "local" {
			local++
			if origin.LocalPath != "./" || byID[origin.Occurrence].Name != "sample" {
				t.Fatalf("Pixi local source: %#v", origin)
			}
		}
	}
	if local != 2 {
		t.Fatalf("Pixi local occurrence count: %d", local)
	}
	all := scanPixi(t, fixture, "--all")
	if all.Coverage.Packages != 19 || dotnetIssue(all, "collector_skipped_missing_lockfile") {
		t.Fatalf("Pixi pyproject --all coverage: %#v", all.Coverage)
	}
}

func TestPixiPyprojectGroupCycle(t *testing.T) {
	root := t.TempDir()
	lock, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", "pixi-pyproject", "pixi.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pixi.lock"), lock, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `[project]
name = "cycle"

[dependency-groups]
a = [{ include-group = "b" }]
b = [{ include-group = "a" }]

[tool.pixi.workspace]
platforms = ["linux-64", "osx-arm64"]

[tool.pixi.environments]
default = { features = ["a"] }
docs = { features = ["a"] }
dev = { features = ["a"] }
all = { features = ["a"] }
`
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := scanPixi(t, root)
	if doc.Coverage.Packages != 19 || !dotnetIssue(doc, "pixi_manifest_group_unresolved") {
		t.Fatalf("Pixi cyclic group was not reported: %#v", doc.Coverage)
	}
	for _, edge := range doc.Edges {
		if edge.Kind == "direct" {
			t.Fatalf("invented Pixi direct root from cyclic group: %#v", edge)
		}
	}
}

func TestPixiDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "pixi-v7")
	root := t.TempDir()
	nested := filepath.Join(root, "pixi")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pixi.lock", "pixi.toml"} {
		data, err := os.ReadFile(filepath.Join(fixture, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(nested, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{nested}, {nested, "--manager", "pixi"}, {root, "--all", "--recursive"}} {
		doc := scanPixi(t, args[0], args[1:]...)
		if doc.Coverage.Packages != 9 || doc.Coverage.Edges != 12 {
			t.Fatalf("Pixi discovery %v: %#v", args, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", filepath.Join(fixture, "pixi.lock"), "--format", format).Output()
		if err != nil || !json.Valid(out) {
			t.Fatalf("Pixi %s export: %v", format, err)
		}
	}
}
