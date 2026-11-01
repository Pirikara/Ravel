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

func TestExpandedEcosystemsRecursiveScan(t *testing.T) {
	root := t.TempDir()
	for _, fixture := range []string{"julia-v2", "renv-basic", "sbt-basic", "rebar-basic", "conda-lock-basic", "pixi-v7", "shards-v2"} {
		source := filepath.Join("..", "testdata", "fixtures", fixture)
		destination := filepath.Join(root, fixture)
		if err := os.Mkdir(destination, 0o755); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(source, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(destination, entry.Name()), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	args := []string{"scan", root, "--all", "--recursive", "--format", "ravel-json"}
	out, err := exec.Command(executable, args...).Output()
	if err != nil {
		t.Fatalf("mixed scan: %v", err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Manager != "multi" || doc.Coverage.Packages != 30 || doc.Coverage.Edges != 14 || len(doc.Coverage.Inputs) != 7 || len(doc.Sources) != 9 {
		t.Fatalf("mixed coverage: %#v", doc.Coverage)
	}
	managers := map[string]bool{}
	for _, input := range doc.Coverage.Inputs {
		managers[input.Manager] = true
	}
	for _, manager := range []string{"julia", "renv", "sbt", "rebar", "conda-lock", "pixi", "shards"} {
		if !managers[manager] {
			t.Fatalf("missing %s in mixed scan: %#v", manager, doc.Coverage.Inputs)
		}
	}
	ids := map[string]bool{}
	for _, component := range doc.Components {
		if ids[component.ID] {
			t.Fatalf("duplicate merged ID: %s", component.ID)
		}
		ids[component.ID] = true
	}
	for _, edge := range doc.Edges {
		if edge.From != "root" && !ids[edge.From] || !ids[edge.To] {
			t.Fatalf("dangling mixed edge: %#v", edge)
		}
	}
	for _, origin := range doc.Origins {
		if !ids[origin.Occurrence] {
			t.Fatalf("dangling mixed origin: %#v", origin)
		}
	}
	if strings.Contains(string(out), "secret") || strings.Contains(string(out), "hidden") {
		t.Fatal("mixed scan leaked URL credentials")
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		args := []string{"scan", root, "--all", "--recursive", "--format", format}
		out, err := exec.Command(executable, args...).Output()
		if err != nil || !json.Valid(out) || strings.Contains(string(out), "secret") {
			t.Fatalf("mixed %s export: %v", format, err)
		}
	}
}
