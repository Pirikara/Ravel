package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/vex"
)

func TestOpenVEXCorrelationCLI(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "npm.ravel.json")
	fixture := filepath.Join("..", "testdata", "fixtures", "npm-generated-12")
	if out, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", sbom).CombinedOutput(); err != nil {
		t.Fatalf("scan: %v\n%s", err, out)
	}
	vexPath := filepath.Join("..", "testdata", "openvex", "npm-products.json")
	out, err := exec.Command(executable, "vex", "--input", sbom, "--vex", vexPath, "--format", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("vex: %v\n%s", err, out)
	}
	var result vex.Result
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	if result.Author != "Example Security Team" || !strings.HasPrefix(result.InputDigest, "sha256:") || len(result.Statements) != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	first := result.Statements[0]
	if first.Status != "under_investigation" || len(first.Products) != 2 || !first.Products[0].Matched || first.Products[0].MatchMethod != "exact_purl" || len(first.Products[0].ComponentIDs) != 1 || first.Products[1].Matched || first.Products[1].Reason != "purl_not_in_sbom" {
		t.Fatalf("unexpected first statement: %+v", first)
	}
	second := result.Statements[1]
	if second.Status != "not_affected" || !second.Products[0].Matched || second.Products[0].PURL != "pkg:npm/is-number@7.0.0" || len(second.Products[0].SubcomponentPURLs) != 1 {
		t.Fatalf("unexpected second statement: %+v", second)
	}
	textOut, err := exec.Command(executable, "vex", "--input", sbom, "--vex", vexPath).CombinedOutput()
	if err != nil || !strings.Contains(string(textOut), "issuer's status") || !strings.Contains(string(textOut), "unmatched product") || !strings.Contains(string(textOut), "not correlated") {
		t.Fatalf("text output: %v\n%s", err, textOut)
	}
}

func TestOpenVEXRejectsInvalidAndProtectsInputs(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "scan.ravel.json")
	if err := os.WriteFile(sbom, []byte(`{"schemaVersion":"0.1","components":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	vexPath := filepath.Join(dir, "vex.json")
	base := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1","author":"Example","timestamp":"2026-10-01T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-1"},"products":[{"@id":"pkg:npm/alpha@1.0.0"}],"status":"not_affected"}]}`
	if err := os.WriteFile(vexPath, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(executable, "vex", "--input", sbom, "--vex", vexPath).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "requires justification or impact_statement") {
		t.Fatalf("expected validation error: %v\n%s", err, out)
	}
	if out, err := exec.Command(executable, "vex", "--input", sbom, "--vex", vexPath, "--output", vexPath).CombinedOutput(); err == nil {
		t.Fatalf("expected overwrite rejection: %s", out)
	}
	if data, err := os.ReadFile(vexPath); err != nil || string(data) != base {
		t.Fatalf("VEX input changed: %v", err)
	}
}
