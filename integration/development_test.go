package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestVCSOriginsBecomeDevelopmentCandidates(t *testing.T) {
	for _, name := range []string{"cargo-git", "composer-basic", "swift-v2", "pub-git", "cocoapods-git"} {
		t.Run(name, func(t *testing.T) {
			fixture := filepath.Join("..", "testdata", "fixtures", name)
			output := filepath.Join(t.TempDir(), "ravel.json")
			if out, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", output).CombinedOutput(); err != nil {
				t.Fatalf("scan failed: %v: %s", err, out)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var doc model.Document
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			vcsCount := 0
			for _, origin := range doc.Origins {
				if origin.Kind != "vcs" {
					continue
				}
				vcsCount++
				found := false
				for _, source := range doc.Development {
					if source.Occurrence == origin.Occurrence && source.SafeURL == origin.SafeURL && source.Status == "inferred_from_vcs_source" {
						found = true
					}
				}
				if !found {
					t.Fatalf("VCS source missing as development candidate: %#v", origin)
				}
			}
			if vcsCount == 0 {
				t.Fatal("fixture contains no VCS origin")
			}
		})
	}
}

func TestCycloneDXDoesNotDuplicateVCSReference(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "composer-basic")
	output := filepath.Join(t.TempDir(), "sbom.json")
	if out, err := exec.Command(executable, "scan", fixture, "--output", output).CombinedOutput(); err != nil {
		t.Fatalf("scan failed: %v: %s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Components []struct {
			Name               string `json:"name"`
			ExternalReferences []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"externalReferences"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	for _, component := range bom.Components {
		if component.Name != "monolog/monolog" {
			continue
		}
		count := 0
		for _, ref := range component.ExternalReferences {
			if ref.Type == "vcs" && ref.URL == "https://github.com/Seldaek/monolog.git" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("duplicate CycloneDX VCS reference: %d", count)
		}
		return
	}
	t.Fatal("Composer package missing")
}
