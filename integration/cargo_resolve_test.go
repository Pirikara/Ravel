package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestCargoResolverWithRealCargo(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("Cargo is not installed")
	}
	project := t.TempDir()
	for _, pkg := range []struct {
		dir, manifest string
	}{
		{"", `[package]
name = "ravel-cargo-test-app"
version = "0.1.0"
edition = "2021"
[dependencies]
alpha = { path = "alpha" }
`},
		{"alpha", `[package]
name = "alpha"
version = "1.0.0"
edition = "2021"
repository = "https://user:secret@example.test/alpha?token=hidden"
[dependencies]
beta = { path = "../beta" }
`},
		{"beta", `[package]
name = "beta"
version = "2.0.0"
edition = "2021"
`},
	} {
		dir := filepath.Join(project, pkg.dir)
		if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(pkg.manifest), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "src", "lib.rs"), []byte("pub fn item() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if output, code := mavenScan(t, project); code != 2 || !strings.Contains(string(output), "--resolve --allow-exec") {
		t.Fatalf("expected Cargo static refusal, code=%d output=%s", code, output)
	}
	result := filepath.Join(t.TempDir(), "cargo.json")
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("Cargo resolver failed, code=%d output=%s", code, output)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Manager != "cargo" || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 || doc.Coverage.GraphState != "complete_for_scope" {
		t.Fatalf("Cargo graph incorrect: %#v", doc)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
		if component.Kind != "application" || component.PURL != "" {
			t.Fatalf("local Cargo package asserted registry identity: %#v", component)
		}
	}
	if ids["alpha"] == "" || ids["beta"] == "" {
		t.Fatalf("Cargo path packages missing: %#v", doc.Components)
	}
	var rootToAlpha, alphaToBeta bool
	for _, edge := range doc.Edges {
		rootToAlpha = rootToAlpha || edge.From == "root" && edge.To == ids["alpha"]
		alphaToBeta = alphaToBeta || edge.From == ids["alpha"] && edge.To == ids["beta"]
	}
	if !rootToAlpha || !alphaToBeta {
		t.Fatalf("Cargo dependency edges missing: %#v", doc.Edges)
	}
	if len(doc.Development) != 1 || doc.Development[0].Occurrence != ids["alpha"] || doc.Development[0].SafeURL != "https://example.test/alpha" || strings.Contains(string(data), "secret") || strings.Contains(string(data), "hidden") {
		t.Fatalf("Cargo development repository missing or unsanitized: %#v", doc.Development)
	}
	lock := filepath.Join(project, "Cargo.lock")
	if _, err := os.Stat(lock); err != nil {
		t.Fatalf("Cargo did not create lockfile: %v", err)
	}
	if output, code := mavenScan(t, project, "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("Cargo static lockfile scan failed, code=%d output=%s", code, output)
	}
	data, _ = os.ReadFile(result)
	if err := json.Unmarshal(data, &doc); err != nil || doc.Coverage.GraphState != "partial" {
		t.Fatalf("Cargo static lockfile not preferred: %v %#v", err, doc.Coverage)
	}
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("Cargo --locked resolver failed, code=%d output=%s", code, output)
	}
	if output, code := mavenScan(t, project, "--output", filepath.Join(project, "Cargo.toml")); code != 2 || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("Cargo.toml overwrite not blocked, code=%d output=%s", code, output)
	}
	if output, code := mavenScan(t, project, "--output", lock); code != 2 || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("Cargo.lock overwrite not blocked, code=%d output=%s", code, output)
	}
}

func TestCargoResolverVirtualWorkspace(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("Cargo is not installed")
	}
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "Cargo.toml"), []byte("[workspace]\nmembers = [\"alpha\", \"beta\"]\nresolver = \"2\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, pkg := range []struct {
		name, dependencies string
	}{
		{"alpha", "[dependencies]\nbeta = { path = \"../beta\" }\n"},
		{"beta", ""},
	} {
		dir := filepath.Join(project, pkg.name)
		if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
			t.Fatal(err)
		}
		manifest := "[package]\nname = \"" + pkg.name + "\"\nversion = \"1.0.0\"\nedition = \"2021\"\n" + pkg.dependencies
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "src", "lib.rs"), []byte("pub fn item() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	result := filepath.Join(t.TempDir(), "workspace.json")
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("Cargo workspace resolution failed, code=%d output=%s", code, output)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "complete_for_scope" {
		t.Fatalf("Cargo workspace graph incorrect: %#v", doc)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
	}
	var alphaToBeta, rootToAlpha, rootToBeta bool
	for _, edge := range doc.Edges {
		alphaToBeta = alphaToBeta || edge.From == ids["alpha"] && edge.To == ids["beta"]
		rootToAlpha = rootToAlpha || edge.From == "root" && edge.To == ids["alpha"]
		rootToBeta = rootToBeta || edge.From == "root" && edge.To == ids["beta"]
	}
	if !alphaToBeta || !rootToAlpha || !rootToBeta {
		t.Fatalf("Cargo workspace edges missing: %#v", doc.Edges)
	}
}
