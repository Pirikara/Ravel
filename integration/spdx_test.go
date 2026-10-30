package integration_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"ravel/internal/model"
)

func TestSPDX23AllFixtures(t *testing.T) {
	schemaBytes, err := os.ReadFile(filepath.Join("..", "testdata", "schema", "spdx-2.3.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaBytes, &schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	const schemaID = "https://spdx.org/rdf/terms/2.3"
	if err := compiler.AddResource(schemaID, schemaDocument); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(schemaID)
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := os.ReadDir(filepath.Join("..", "testdata", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range fixtures {
		name := entry.Name()
		if !entry.IsDir() || name == "bun-legacy" || strings.HasSuffix(name, "-unsupported") || strings.HasPrefix(name, "java-") {
			continue
		}
		count++
		t.Run(name, func(t *testing.T) {
			fixture := filepath.Join("..", "testdata", "fixtures", name)
			spdxPath := filepath.Join(t.TempDir(), "sbom.spdx.json")
			ravelPath := filepath.Join(t.TempDir(), "ravel.json")
			cmd := exec.Command(executable, "scan", fixture, "--format", "spdx-json", "--output", spdxPath)
			cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=1700000000")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("SPDX scan failed: %v: %s", err, out)
			}
			if out, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", ravelPath).CombinedOutput(); err != nil {
				t.Fatalf("Ravel scan failed: %v: %s", err, out)
			}
			spdxBytes, err := os.ReadFile(spdxPath)
			if err != nil {
				t.Fatal(err)
			}
			var raw any
			if err := json.Unmarshal(spdxBytes, &raw); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(raw); err != nil {
				t.Fatalf("SPDX schema failed: %v", err)
			}
			ravelBytes, err := os.ReadFile(ravelPath)
			if err != nil {
				t.Fatal(err)
			}
			var doc model.Document
			if err := json.Unmarshal(ravelBytes, &doc); err != nil {
				t.Fatal(err)
			}
			var output struct {
				Version           string   `json:"spdxVersion"`
				DocumentDescribes []string `json:"documentDescribes"`
				CreationInfo      struct {
					Created string `json:"created"`
				} `json:"creationInfo"`
				Packages []struct {
					ID               string `json:"SPDXID"`
					Name             string `json:"name"`
					Comment          string `json:"comment"`
					DownloadLocation string `json:"downloadLocation"`
					FilesAnalyzed    bool   `json:"filesAnalyzed"`
					ExternalRefs     []struct {
						Type    string `json:"referenceType"`
						Locator string `json:"referenceLocator"`
					} `json:"externalRefs"`
				} `json:"packages"`
				Relationships []struct {
					From string `json:"spdxElementId"`
					Type string `json:"relationshipType"`
					To   string `json:"relatedSpdxElement"`
				} `json:"relationships"`
			}
			if err := json.Unmarshal(spdxBytes, &output); err != nil {
				t.Fatal(err)
			}
			if output.Version != "SPDX-2.3" || output.CreationInfo.Created != "2023-11-14T22:13:20Z" || len(output.Packages) != len(doc.Components)+1 || len(output.DocumentDescribes) != 1 || output.DocumentDescribes[0] != "SPDXRef-Root" {
				t.Fatalf("unexpected SPDX document structure: %+v", output)
			}
			ids := map[string]bool{}
			purls := map[string]int{}
			for _, pkg := range output.Packages {
				if ids[pkg.ID] || pkg.DownloadLocation != "NOASSERTION" || pkg.FilesAnalyzed {
					t.Fatalf("invalid or duplicate package: %+v", pkg)
				}
				ids[pkg.ID] = true
				for _, ref := range pkg.ExternalRefs {
					if ref.Type == "purl" {
						purls[ref.Locator]++
					}
				}
			}
			for _, c := range doc.Components {
				if c.PURL != "" && purls[c.PURL] == 0 {
					t.Fatalf("missing PURL %s", c.PURL)
				}
				if c.Context != "" {
					found := false
					for _, pkg := range output.Packages {
						if pkg.Name == c.Name && pkg.Comment == "Ravel context: "+c.Context {
							found = true
						}
					}
					if !found {
						t.Fatalf("missing SPDX context for %s", c.Name)
					}
				}
			}
			unconditional := map[string]bool{}
			for _, edge := range doc.Edges {
				if edge.Condition == "" {
					unconditional[edge.From+"\x00"+edge.To] = true
				}
			}
			if len(output.Relationships) != len(unconditional) {
				t.Fatalf("conditional edges exported or unconditional edges lost: got %d, want %d", len(output.Relationships), len(unconditional))
			}
			for _, rel := range output.Relationships {
				if rel.Type != "DEPENDS_ON" || !ids[rel.From] || !ids[rel.To] {
					t.Fatalf("invalid SPDX relationship: %+v", rel)
				}
			}
			if (name == "npm-v3" || name == "npm-v1-optional" || name == "npm-v1-sources" || name == "cocoapods-git" || name == "pipenv-sources" || name == "pdm-sources") && (strings.Contains(string(spdxBytes), "hidden") || strings.Contains(string(spdxBytes), "secret")) {
				t.Fatal("credential leaked into SPDX output")
			}
		})
	}
	if count != 141 {
		t.Fatalf("SPDX fixture suite omitted a known fixture: got %d, want 141", count)
	}
}

func TestSPDXReproducibleTimestampAndInvalidEpoch(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "pub-basic")
	first := filepath.Join(t.TempDir(), "first.json")
	second := filepath.Join(t.TempDir(), "second.json")
	for _, path := range []string{first, second} {
		cmd := exec.Command(executable, "scan", fixture, "--format", "spdx-json", "--output", path)
		cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=1700000000")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("SPDX scan failed: %v: %s", err, out)
		}
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("fixed SOURCE_DATE_EPOCH did not produce identical SPDX documents")
	}
	invalid := filepath.Join(t.TempDir(), "invalid.json")
	cmd := exec.Command(executable, "scan", fixture, "--format", "spdx-json", "--output", invalid)
	cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=invalid")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "invalid SOURCE_DATE_EPOCH") {
		t.Fatalf("invalid SOURCE_DATE_EPOCH was accepted: %v: %s", err, out)
	}
	if _, err := os.Stat(invalid); !os.IsNotExist(err) {
		t.Fatal("invalid SOURCE_DATE_EPOCH wrote an SPDX document")
	}
}
