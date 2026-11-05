package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/export"
	"github.com/Pirikara/Ravel/internal/merge"
	"github.com/Pirikara/Ravel/internal/model"
)

func TestDeclaredRootIdentityAndExport(t *testing.T) {
	cases := []struct {
		fixture, manifest, name, version string
	}{
		{"yarn-classic-mixed-alias", "package.json", "mixed-alias", "1.0.0"},
		{"cargo-basic", "Cargo.toml", "demo", "0.1.0"},
		{"pub-bbp-wallet", "pubspec.yaml", "flutter", "1.0.0"},
	}
	var inputs []model.Document
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			fixture := filepath.Join("..", "testdata", "fixtures", tc.fixture)
			output := filepath.Join(t.TempDir(), "ravel.json")
			if data, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", output).CombinedOutput(); err != nil {
				t.Fatalf("scan failed: %v: %s", err, data)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var doc model.Document
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Root == nil || doc.Root.Name != tc.name || doc.Root.Version != tc.version || filepath.Base(doc.Root.Evidence.InputPath) != tc.manifest || !strings.HasPrefix(doc.Root.Evidence.InputDigest, "sha256:") {
				t.Fatalf("root identity or evidence missing: %#v", doc.Root)
			}
			inputs = append(inputs, doc)
			cyclone, err := export.CycloneDX(doc)
			if err != nil {
				t.Fatal(err)
			}
			var cdx struct {
				Metadata struct {
					Component struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"component"`
				} `json:"metadata"`
			}
			if err := json.Unmarshal(cyclone, &cdx); err != nil {
				t.Fatal(err)
			}
			if cdx.Metadata.Component.Name != tc.name || cdx.Metadata.Component.Version != tc.version {
				t.Fatalf("CycloneDX root differs from manifest: %#v", cdx.Metadata.Component)
			}
			t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
			spdx, err := export.SPDX23(doc)
			if err != nil {
				t.Fatal(err)
			}
			var parsed struct {
				Packages []struct {
					ID      string `json:"SPDXID"`
					Name    string `json:"name"`
					Version string `json:"versionInfo"`
				} `json:"packages"`
			}
			if err := json.Unmarshal(spdx, &parsed); err != nil {
				t.Fatal(err)
			}
			if len(parsed.Packages) == 0 || parsed.Packages[0].ID != "SPDXRef-Root" || parsed.Packages[0].Name != tc.name || parsed.Packages[0].Version != tc.version {
				t.Fatalf("SPDX root differs from manifest: %#v", parsed.Packages)
			}
		})
	}
	merged, err := merge.Documents("polyglot", inputs)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Root != nil {
		t.Fatalf("one input's root identity was attributed to a multi-project scan: %#v", merged.Root)
	}
	applications := map[string]model.Component{}
	for _, component := range merged.Components {
		if component.Kind == "application" {
			applications[component.Name] = component
		}
	}
	if len(applications) != len(cases) {
		t.Fatalf("merged input roots missing: %#v", applications)
	}
	for i, tc := range cases {
		application, found := applications[tc.name]
		if !found || application.Version != tc.version || len(application.Evidence) != 1 || application.Evidence[0] != inputs[i].Root.Evidence {
			t.Fatalf("merged root identity or evidence missing for %s: %#v", tc.name, application)
		}
		var rootLink, outgoing int
		for _, edge := range merged.Edges {
			if edge.From == "root" && edge.To == application.ID {
				rootLink++
			}
			if edge.From == application.ID {
				outgoing++
			}
		}
		var inputDirect int
		for _, edge := range inputs[i].Edges {
			if edge.From == "root" {
				inputDirect++
			}
		}
		if rootLink != 1 || outgoing != inputDirect {
			t.Fatalf("merged root edges differ for %s: root=%d outgoing=%d input=%d", tc.name, rootLink, outgoing, inputDirect)
		}
	}
	for _, edge := range merged.Edges {
		if edge.From == "root" {
			if _, found := applications[componentName(merged.Components, edge.To)]; !found {
				t.Fatalf("merged root bypasses an input application: %#v", edge)
			}
		}
	}
	cyclone, err := export.CycloneDX(merged)
	if err != nil {
		t.Fatal(err)
	}
	var cdx struct {
		Metadata struct {
			Component struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(cyclone, &cdx); err != nil {
		t.Fatal(err)
	}
	if cdx.Metadata.Component.Name != "polyglot" || cdx.Metadata.Component.Version != "" {
		t.Fatalf("merged project inherited an input identity: %#v", cdx.Metadata.Component)
	}
	nested, err := merge.Documents("larger-scope", []model.Document{merged, common.NewDocument("other", "other", "synthetic", nil)})
	if err != nil {
		t.Fatal(err)
	}
	var nestedApplications, nestedRootEdges int
	for _, component := range nested.Components {
		if component.Kind == "application" && applications[component.Name].Name != "" {
			nestedApplications++
		}
	}
	for _, edge := range nested.Edges {
		if edge.From == "root" {
			nestedRootEdges++
		}
	}
	if nestedApplications != len(cases) || nestedRootEdges != len(cases) {
		t.Fatalf("nested merge lost scoped root applications: applications=%d rootEdges=%d", nestedApplications, nestedRootEdges)
	}
}

func componentName(components []model.Component, id string) string {
	for _, component := range components {
		if component.ID == id {
			return component.Name
		}
	}
	return ""
}
