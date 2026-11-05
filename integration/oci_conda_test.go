package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func condaFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "oci", "conda-meta", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOCICondaInstalledMetadata(t *testing.T) {
	const prefix = "opt/conda/conda-meta/"
	packages := []string{"python-3.12.7-h123_0.json", "zlib-1.3.1-h2_0.json", "pip-24.2-pyhd8ed1ab_0.json", "_libgcc_mutex-0.1-main.json", "_openmp_mutex-5.1-52_gnu.json"}
	entries := make([]ociTestEntry, 0, len(packages))
	for _, name := range packages {
		entries = append(entries, ociTestEntry{name: prefix + name, data: condaFixture(t, name)})
	}
	layout := ociTestLayout(t)
	ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: entries}}))
	for _, input := range []string{layout, ociTestArchive(t, layout, "conda.oci.tar")} {
		doc, output, code := ociTestScan(t, input)
		if code != 0 || doc.Coverage.Packages != 5 || doc.Coverage.Edges != 5 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" || !dotnetIssue(doc, "conda_dependency_graph_unavailable") || !dotnetIssue(doc, "conda_distribution_origin_unverified") {
			t.Fatalf("Conda OCI scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
		}
		for _, tc := range []struct{ name, version, filename string }{
			{"python", "3.12.7", packages[0]}, {"zlib", "1.3.1", packages[1]}, {"pip", "24.2", packages[2]}, {"_libgcc_mutex", "0.1", packages[3]}, {"_openmp_mutex", "5.1", packages[4]},
		} {
			component := dotnetComponent(t, doc, tc.name)
			digest := sha256.Sum256(condaFixture(t, tc.filename))
			if component.Version != tc.version || component.PURL != "" || !strings.HasPrefix(component.Context, "environment=/opt/conda;build=") || len(component.Evidence) != 1 || component.Evidence[0].InputDigest != "sha256:"+hex.EncodeToString(digest[:]) || !strings.HasSuffix(component.Evidence[0].InputPath, "!/"+prefix+tc.filename) {
				t.Fatalf("Conda package evidence incorrect: %#v", component)
			}
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		data, err := exec.Command(executable, "scan", layout, "--format", format).Output()
		if err != nil || !json.Valid(data) || strings.Contains(string(data), "example.invalid") {
			t.Fatalf("Conda %s export failed or disclosed unverified channel: %v", format, err)
		}
		var exported struct {
			Components []struct {
				Name string `json:"name"`
				PURL string `json:"purl"`
			} `json:"components"`
			Packages []struct {
				Name         string `json:"name"`
				ExternalRefs []any  `json:"externalRefs"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(data, &exported); err != nil {
			t.Fatal(err)
		}
		if format == "cyclonedx-json" {
			if len(exported.Components) != 5 {
				t.Fatalf("CycloneDX Conda package count = %d", len(exported.Components))
			}
			for _, component := range exported.Components {
				if component.PURL != "" {
					t.Fatalf("Conda PURL without verified origin: %s", component.PURL)
				}
			}
		} else {
			if len(exported.Packages) != 6 {
				t.Fatalf("SPDX Conda package count including root = %d", len(exported.Packages))
			}
			for _, pkg := range exported.Packages[1:] {
				if len(pkg.ExternalRefs) != 0 {
					t.Fatalf("Conda SPDX external reference without verified origin: %s", pkg.Name)
				}
			}
		}
	}
}

func TestOCICondaRecordedArchiveURL(t *testing.T) {
	const filename = "python-3.12.7-h123_0.json"
	const archiveURL = "https://repo.example.test/main/linux-aarch64/python-3.12.7-h123_0.conda"
	var record map[string]any
	if err := json.Unmarshal(condaFixture(t, filename), &record); err != nil {
		t.Fatal(err)
	}
	record["url"] = archiveURL + "?token=secret"
	record["fn"] = "python-3.12.7-h123_0.conda"
	record["channel"] = "https://repo.example.test/main/linux-aarch64"
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	layout := ociTestLayout(t)
	ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{{name: "opt/conda/conda-meta/" + filename, data: data}}}}))
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Origins) != 1 || doc.Origins[0].SafeURL != archiveURL || doc.Origins[0].Status != "recorded_in_install_metadata" || doc.Components[0].PURL != "" {
		t.Fatalf("recorded Conda URL missing or overclaimed: code=%d output=%s doc=%#v", code, output, doc)
	}
	cdx, err := exec.Command(executable, "scan", layout, "--format", "cyclonedx-json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var exported struct {
		Components []struct {
			ExternalReferences []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"externalReferences"`
		} `json:"components"`
	}
	if err := json.Unmarshal(cdx, &exported); err != nil || len(exported.Components) != 1 || len(exported.Components[0].ExternalReferences) != 1 || exported.Components[0].ExternalReferences[0].Type != "distribution" || exported.Components[0].ExternalReferences[0].URL != archiveURL {
		t.Fatalf("Conda URL absent from CycloneDX: err=%v output=%s", err, cdx)
	}
}

func TestOCICondaOverlayAndInvalidMetadata(t *testing.T) {
	const python = "opt/conda/conda-meta/python-3.12.7-h123_0.json"
	const zlib = "opt/conda/conda-meta/zlib-1.3.1-h2_0.json"
	for _, tc := range []struct {
		name      string
		replace   ociTestEntry
		wantIssue string
		wantCount int
	}{
		{"whiteout", ociTestEntry{name: "opt/conda/conda-meta/.wh.python-3.12.7-h123_0.json"}, "", 1},
		{"opaque directory", ociTestEntry{name: "opt/conda/conda-meta/.wh..wh..opq"}, "", 0},
		{"symlink", ociTestEntry{name: python, typeflag: tar.TypeSymlink, linkname: "elsewhere.json"}, "conda_installed_metadata_link_unresolved", 1},
		{"oversized", ociTestEntry{name: python, data: make([]byte, (1<<20)+1)}, "conda_installed_metadata_oversized", 1},
		{"invalid identity", ociTestEntry{name: python, data: []byte(`{"name":"other","version":"3.12.7","build":"h123_0"}`)}, "conda_installed_metadata_invalid", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{
				{entries: []ociTestEntry{{name: python, data: condaFixture(t, filepath.Base(python))}, {name: zlib, data: condaFixture(t, filepath.Base(zlib))}}},
				{entries: []ociTestEntry{tc.replace}},
			}))
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || doc.Coverage.Packages != tc.wantCount {
				t.Fatalf("Conda overlay incorrect: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
			}
			if tc.wantIssue != "" && !dotnetIssue(doc, tc.wantIssue) {
				t.Fatalf("Conda replacement issue absent: %#v", doc.Coverage.Issues)
			}
			for _, component := range doc.Components {
				if component.Name == "python" {
					t.Fatalf("stale Conda package survived overlay: %#v", component)
				}
			}
		})
	}
}
