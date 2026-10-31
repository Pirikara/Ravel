package integration_test

import (
	"archive/tar"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ravel/internal/model"
)

func rpmFixtureDatabase(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "testdata", "fixtures", name)
	if strings.HasPrefix(name, "rpm-sqlite-") {
		path = filepath.Join(path, "usr", "lib", "sysimage", "rpm", "rpmdb.sqlite")
	} else if name == "rpm-bdb-basic" {
		path = filepath.Join(path, "var", "lib", "rpm", "Packages")
	} else {
		path = filepath.Join(path, "var", "lib", "rpm", "Packages.db")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRPMConstraintCases(t *testing.T) {
	for _, fixture := range []string{"rpm-sqlite-constraints", "rpm-ndb-constraints"} {
		t.Run(fixture, func(t *testing.T) { testRPMConstraintCases(t, fixture) })
	}
}

func testRPMConstraintCases(t *testing.T, fixture string) {
	root := filepath.Join("..", "testdata", "fixtures", fixture)
	result := filepath.Join(t.TempDir(), "rpm.json")
	output, err := exec.Command(executable, "scan", root, "--manager", "rpm", "--format", "ravel-json", "--output", result).CombinedOutput()
	if err != nil {
		t.Fatalf("RPM constraint fixture scan failed: %v: %s", err, output)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 8 || doc.Coverage.Edges != 16 || doc.Coverage.GraphState != "partial" {
		t.Fatalf("RPM constraint coverage incorrect: %#v", doc.Coverage)
	}
	names := map[string]string{}
	for _, component := range doc.Components {
		names[component.ID] = component.Name
	}
	conditions := map[string]string{}
	evrEdges := map[string]bool{}
	for _, edge := range doc.Edges {
		if edge.Kind == "depends_on" {
			conditions[names[edge.From]] = edge.Condition
			wantTarget := "ravel-fixture-base"
			if names[edge.From] == "ravel-fixture-file-consumer" {
				wantTarget = "ravel-fixture-file-provider"
				if edge.Evidence.Pointer != "requires//usr/share/ravel-fixture/tool" {
					t.Fatalf("RPM owned-file edge lacks exact path evidence: %#v", edge)
				}
			} else if names[edge.From] == "ravel-fixture-evr-consumer" {
				wantTarget = "ravel-fixture-evr-provider"
				evrEdges[strings.TrimPrefix(edge.Evidence.Pointer, "requires/")] = true
				if edge.Condition != "" {
					t.Fatalf("settled RPM version constraint remained conditional: %#v", edge)
				}
			}
			if names[edge.To] != wantTarget {
				t.Fatalf("RPM dependency linked to unexpected provider: %#v", edge)
			}
		}
	}
	if condition, ok := conditions["ravel-fixture-consumer-unversioned"]; !ok || condition != "" {
		t.Fatalf("unversioned RPM dependency not verified: %#v", conditions)
	}
	if _, linked := conditions["ravel-fixture-consumer-mismatch"]; linked {
		t.Fatalf("mismatched RPM version was linked to an unsatisfying provider: %#v", conditions)
	}
	if _, linked := conditions["ravel-fixture-self"]; linked {
		t.Fatalf("self-provided RPM requirement produced an inter-package edge: %#v", conditions)
	}
	if condition, linked := conditions["ravel-fixture-file-consumer"]; !linked || condition != "" {
		t.Fatalf("RPM owned-file requirement was not verified: %#v", conditions)
	}
	for _, name := range []string{"ravel-fixture-evr-gt", "ravel-fixture-evr-lt", "ravel-fixture-evr-release", "ravel-fixture-evr-no-release", "ravel-fixture-evr-pre", "ravel-fixture-evr-separator"} {
		if !evrEdges[name] {
			t.Fatalf("RPM version constraint %s was not linked: %#v", name, evrEdges)
		}
	}
	if len(evrEdges) != 6 {
		t.Fatalf("RPM version fixture produced extra edges: %#v", evrEdges)
	}
	unresolved := false
	richUnparsed := false
	missingFiles := map[string]bool{}
	evrUnresolved := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		unresolved = unresolved || issue.Code == "unresolved_dependency" && issue.Scope == "ravel-fixture-consumer-mismatch"
		richUnparsed = richUnparsed || issue.Code == "rpm_requirement_unparsed" && issue.Scope == "ravel-fixture-self" && strings.HasPrefix(issue.Name, "(")
		if issue.Code == "rpm_file_requirement_unresolved" && issue.Scope == "ravel-fixture-file-consumer" {
			missingFiles[issue.Name] = true
		}
		if issue.Code == "unresolved_dependency" && issue.Scope == "ravel-fixture-evr-consumer" {
			evrUnresolved[issue.Name] = true
		}
		if issue.Code == "unresolved_dependency" && issue.Scope == "ravel-fixture-self" {
			t.Fatalf("self-provided or Boolean RPM requirement reported missing: %#v", issue)
		}
		if issue.Code == "rpm_dependency_flags_unavailable" || issue.Code == "dependency_constraint_unverified" {
			t.Fatalf("available RPM flags reported missing: %#v", doc.Coverage.Issues)
		}
	}
	if !unresolved || !richUnparsed || !missingFiles["/usr/share/ravel-fixture/ghost"] || !missingFiles["/usr/share/ravel-fixture/absent"] || len(missingFiles) != 2 || !evrUnresolved["ravel-fixture-evr-bad"] || !evrUnresolved["ravel-fixture-evr-release-bad"] || len(evrUnresolved) != 2 {
		t.Fatalf("RPM mismatch, Boolean, or unresolved file requirement was not reported: %#v", doc.Coverage.Issues)
	}
	spdx, err := exec.Command(executable, "scan", root, "--manager", "rpm", "--format", "spdx-json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var exported struct {
		Relationships []json.RawMessage `json:"relationships"`
	}
	if err := json.Unmarshal(spdx, &exported); err != nil || len(exported.Relationships) != 11 {
		t.Fatalf("RPM constraint export included unverified edge: %v, relationships=%d", err, len(exported.Relationships))
	}

	ociDatabasePath := "usr/lib/sysimage/rpm/rpmdb.sqlite"
	if fixture == "rpm-ndb-constraints" {
		ociDatabasePath = "var/lib/rpm/Packages.db"
	}
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: ociDatabasePath, data: rpmFixtureDatabase(t, fixture)},
	}}})
	ociTestIndex(t, layout, image)
	ociDoc, ociOutput, code := ociTestScan(t, layout)
	if code != 0 || ociDoc.Coverage.Packages != 8 || ociDoc.Coverage.Edges != 16 {
		t.Fatalf("OCI RPM constraint scan failed: code=%d output=%s coverage=%#v", code, ociOutput, ociDoc.Coverage)
	}
}

func TestRPMInstalledDatabaseFixtures(t *testing.T) {
	for _, fixture := range []string{"rpm-sqlite-basic", "rpm-ndb-basic", "rpm-bdb-basic"} {
		t.Run(fixture, func(t *testing.T) {
			root := filepath.Join("..", "testdata", "fixtures", fixture)
			databaseFile := filepath.Join(root, "var", "lib", "rpm", "Packages.db")
			if fixture == "rpm-sqlite-basic" {
				databaseFile = filepath.Join(root, "usr", "lib", "sysimage", "rpm", "rpmdb.sqlite")
			} else if fixture == "rpm-bdb-basic" {
				databaseFile = filepath.Join(root, "var", "lib", "rpm", "Packages")
			}
			result := filepath.Join(t.TempDir(), "rpm.json")
			out, err := exec.Command(executable, "scan", root, "--manager", "rpm", "--format", "ravel-json", "--output", result).CombinedOutput()
			if err != nil {
				t.Fatalf("RPM scan failed: %v: %s", err, out)
			}
			data, err := os.ReadFile(result)
			if err != nil {
				t.Fatal(err)
			}
			var doc model.Document
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Coverage.Manager != "rpm" || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "complete_for_scope" || doc.Coverage.OriginState != "partial" {
				t.Fatalf("RPM inventory or coverage incorrect: %#v", doc.Coverage)
			}
			names := map[string]bool{}
			for _, component := range doc.Components {
				names[component.Name+"@"+component.Version] = true
				if component.PURL != "" || component.Platform != "noarch" || component.Evidence[0].Collector != "rpmdb" {
					t.Fatalf("RPM package identity or evidence incorrect: %#v", component)
				}
			}
			if !names["ravel-fixture-base@1.0-1"] || !names["ravel-fixture-consumer@2.0-1"] {
				t.Fatalf("RPM fixture packages missing: %#v", names)
			}
			linked := 0
			for _, edge := range doc.Edges {
				if edge.Kind == "depends_on" {
					linked++
					if edge.Condition != "" || edge.Evidence.Pointer != "requires/ravel-fixture-virtual" {
						t.Fatalf("RPM exact capability match was not verified: %#v", edge)
					}
				}
			}
			if linked != 1 {
				t.Fatalf("RPM capability generated %d dependency edges", linked)
			}
			if output, err := exec.Command(executable, "scan", databaseFile, "--manager", "rpm", "--format", "ravel-json").Output(); err != nil || !json.Valid(output) {
				t.Fatalf("direct RPM database scan failed: %v: %s", err, output)
			}
			for _, format := range []string{"cyclonedx-json", "spdx-json"} {
				data, err := exec.Command(executable, "scan", root, "--manager", "rpm", "--format", format).Output()
				if err != nil || !json.Valid(data) {
					t.Fatalf("RPM %s export failed: %v", format, err)
				}
				if format == "spdx-json" {
					var document struct {
						Relationships []json.RawMessage `json:"relationships"`
					}
					if err := json.Unmarshal(data, &document); err != nil || len(document.Relationships) != 3 {
						t.Fatalf("verified RPM edge missing from SPDX: %v, relationships=%d", err, len(document.Relationships))
					}
				}
			}
		})
	}
}

func TestOCIRPMDatabaseAndDirectoryLinks(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "lib", typeflag: tar.TypeSymlink, linkname: "usr/lib"},
		{name: "var/lib/rpm", typeflag: tar.TypeSymlink, linkname: "../../usr/lib/sysimage/rpm"},
		{name: "usr/lib/sysimage/rpm/rpmdb.sqlite", data: rpmFixtureDatabase(t, "rpm-sqlite-basic")},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 || doc.Coverage.Manager != "oci" {
		t.Fatalf("OCI RPM database scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	for _, component := range doc.Components {
		if component.Evidence[0].Collector != "rpmdb" || !strings.Contains(component.Evidence[0].InputPath, "!/usr/lib/sysimage/rpm/rpmdb.sqlite") {
			t.Fatalf("OCI RPM evidence incorrect: %#v", component)
		}
	}
}

func TestOCIRPMDatabaseFormats(t *testing.T) {
	for _, fixture := range []struct {
		name string
		path string
	}{
		{"rpm-sqlite-basic", "usr/lib/sysimage/rpm/rpmdb.sqlite"},
		{"rpm-ndb-basic", "var/lib/rpm/Packages.db"},
		{"rpm-bdb-basic", "var/lib/rpm/Packages"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: fixture.path, data: rpmFixtureDatabase(t, fixture.name)}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "partial" {
				t.Fatalf("OCI RPM format scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
			}
			for _, edge := range doc.Edges {
				if edge.Kind == "depends_on" && edge.Condition != "" {
					t.Fatalf("OCI RPM exact capability edge stayed conditional: %#v", edge)
				}
			}
		})
	}
}

func TestRPMUncheckpointedWAL(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "usr", "lib", "sysimage", "rpm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rpmdb.sqlite"), rpmFixtureDatabase(t, "rpm-sqlite-basic"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rpmdb.sqlite-wal"), []byte("pending transactions"), 0o644); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(executable, "scan", root, "--manager", "rpm").CombinedOutput()
	if err == nil || !strings.Contains(string(output), "uncheckpointed WAL") {
		t.Fatalf("uncheckpointed RPM WAL was accepted: %v: %s", err, output)
	}
}

func TestRPMDatabaseSelection(t *testing.T) {
	root := t.TempDir()
	sqliteDir := filepath.Join(root, "usr", "lib", "sysimage", "rpm")
	if err := os.MkdirAll(sqliteDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sqliteDir, "rpmdb.sqlite"), rpmFixtureDatabase(t, "rpm-sqlite-basic"), 0o644); err != nil {
		t.Fatal(err)
	}
	aliasDir := filepath.Join(root, "var", "lib")
	if err := os.MkdirAll(aliasDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../usr/lib/sysimage/rpm", filepath.Join(aliasDir, "rpm")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", root, "--manager", "rpm", "--format", "ravel-json"},
		{"scan", root, "--all", "--format", "ravel-json"},
	} {
		output, err := exec.Command(executable, args...).Output()
		if err != nil {
			t.Fatalf("aliased RPM database rejected: %v", err)
		}
		var doc model.Document
		if err := json.Unmarshal(output, &doc); err != nil || doc.Coverage.Packages != 2 {
			t.Fatalf("RPM alias inventory incorrect: %v, coverage=%#v", err, doc.Coverage)
		}
	}
	ndbDir := filepath.Join(root, "usr", "share", "rpm")
	if err := os.MkdirAll(ndbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ndbDir, "Packages.db"), rpmFixtureDatabase(t, "rpm-ndb-basic"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", root, "--manager", "rpm"},
		{"scan", root, "--all"},
	} {
		output, err := exec.Command(executable, args...).CombinedOutput()
		if err == nil || !strings.Contains(string(output), "multiple RPM databases") {
			t.Fatalf("ambiguous RPM rootfs accepted: %v: %s", err, output)
		}
	}
}

func TestOCIRPMWALOverlay(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "whiteout"}[removed], func(t *testing.T) {
			layout := ociTestLayout(t)
			layers := []ociTestLayer{{entries: []ociTestEntry{
				{name: "usr/lib/sysimage/rpm/rpmdb.sqlite", data: rpmFixtureDatabase(t, "rpm-sqlite-basic")},
				{name: "usr/lib/sysimage/rpm/rpmdb.sqlite-wal", data: []byte("pending transactions")},
			}}}
			if removed {
				layers = append(layers, ociTestLayer{entries: []ociTestEntry{{name: "usr/lib/sysimage/rpm/.wh.rpmdb.sqlite-wal"}}})
			}
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", layers))
			doc, output, code := ociTestScan(t, layout)
			if removed {
				if code != 0 || doc.Coverage.Packages != 2 {
					t.Fatalf("whiteout did not remove RPM WAL: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
				}
			} else if code != 1 || !strings.Contains(output, "uncheckpointed WAL") {
				t.Fatalf("uncheckpointed RPM WAL was accepted: code=%d output=%s", code, output)
			}
		})
	}
}
