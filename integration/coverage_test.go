package integration_test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestOutputLossReport(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "npm-v1-optional")
	for _, tc := range []struct {
		format string
		want   map[string]int
	}{
		{"ravel-json", map[string]int{}},
		{"cyclonedx-json", map[string]int{
			"conditional_edges_omitted": 2,
			"edge_kinds_omitted":        1,
			"evidence_records_omitted":  7,
			"source_paths_omitted":      2,
			"origin_statuses_omitted":   2,
		}},
		{"spdx-json", map[string]int{
			"conditional_edges_omitted": 2,
			"edge_kinds_omitted":        1,
			"evidence_records_omitted":  7,
			"source_paths_omitted":      2,
			"origin_records_omitted":    2,
		}},
	} {
		t.Run(tc.format, func(t *testing.T) {
			reportPath := filepath.Join(t.TempDir(), "coverage.json")
			outputPath := filepath.Join(t.TempDir(), "sbom.json")
			cmd := exec.Command(executable, "scan", fixture, "--format", tc.format, "--output", outputPath, "--report", reportPath)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("scan failed: %v: %s", err, output)
			}
			data, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			var report struct {
				OutputFormat string `json:"outputFormat"`
				OutputLosses []struct {
					Code  string `json:"code"`
					Count int    `json:"count"`
				} `json:"outputLosses"`
			}
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if report.OutputFormat != tc.format {
				t.Fatalf("wrong report format: %s", report.OutputFormat)
			}
			got := map[string]int{}
			for _, loss := range report.OutputLosses {
				got[loss.Code] = loss.Count
			}
			for code, count := range tc.want {
				if got[code] != count {
					t.Fatalf("loss %s: got %d, want %d; all losses: %+v", code, got[code], count, got)
				}
			}
			if tc.format == "ravel-json" && len(got) != 0 {
				t.Fatalf("Ravel JSON reported information loss: %+v", got)
			}
		})
	}
	complete := filepath.Join("..", "testdata", "fixtures", "npm-v1-generated-12")
	cmd := exec.Command(executable, "scan", complete, "--strict", "--output", filepath.Join(t.TempDir(), "sbom.json"), "--report", filepath.Join(t.TempDir(), "report.json"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("strict scan failed on export-only losses: %v: %s", err, output)
	}
}

func TestNpmV4StrictPatchCoverage(t *testing.T) {
	for _, tc := range []struct {
		fixture  string
		exitCode int
	}{
		{"npm-v4-generated-12", 0},
		{"npm-v4-range-selector", 0},
		{"npm-v4-patch-missing", 3},
		{"npm-v4-patch-mismatch", 3},
		{"npm-v4-patch-unsafe", 3},
		{"npm-v4-manifest-mismatch", 3},
		{"npm-v4-lock-missing-patch", 3},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "sbom.json")
			reportPath := filepath.Join(t.TempDir(), "report.json")
			fixture := filepath.Join("..", "testdata", "fixtures", tc.fixture)
			cmd := exec.Command(executable, "scan", fixture, "--strict", "--output", outputPath, "--report", reportPath)
			output, err := cmd.CombinedOutput()
			got := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatalf("scan failed: %v: %s", err, output)
				}
				got = exit.ExitCode()
			}
			if got != tc.exitCode {
				t.Fatalf("strict exit code: got %d, want %d: %s", got, tc.exitCode, output)
			}
			if _, err := os.Stat(outputPath); err != nil {
				t.Fatalf("strict scan did not write SBOM: %v", err)
			}
			if _, err := os.Stat(reportPath); err != nil {
				t.Fatalf("strict scan did not write coverage report: %v", err)
			}
		})
	}
}
