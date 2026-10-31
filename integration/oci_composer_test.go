package integration_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOCIComposerInstalledV2Overlay(t *testing.T) {
	const manifestPath = "app/vendor/composer/installed.json"
	data, err := os.ReadFile(filepath.Join("..", "testdata", "oci", "composer-installed-v2", "vendor", "composer", "installed.json"))
	if err != nil {
		t.Fatal(err)
	}
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{{name: manifestPath, data: []byte(`[{"name":"old/removed","version":"0.1.0"}]`)}}},
		{gzip: true, entries: []ociTestEntry{{name: "app/vendor/composer/.wh.installed.json"}, {name: manifestPath, data: data}}},
	})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "partial" {
		t.Fatalf("OCI Composer 2 inventory failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	names := map[string]string{}
	for _, component := range doc.Components {
		names[component.ID] = component.Name
		if component.Evidence[0].Collector != "composer-installed" || !strings.HasPrefix(component.Evidence[0].InputPath, "oci:sha256:") || !strings.Contains(component.Evidence[0].InputPath, "!/"+manifestPath) || component.Context != "registry="+manifestPath+";image=linux/amd64" || component.PURL != "" {
			t.Fatalf("OCI Composer identity or provenance incorrect: %#v", component)
		}
	}
	if len(names) != 2 {
		t.Fatalf("whiteouted Composer package remained installed: %#v", names)
	}
	linked := false
	for _, edge := range doc.Edges {
		linked = linked || edge.Kind == "depends_on" && names[edge.From] == "acme/alpha" && names[edge.To] == "acme/beta" && edge.Condition == "composer_constraint=unverified" && edge.Evidence.Pointer == "/packages/0/require/acme~1beta"
	}
	if !linked {
		t.Fatalf("Composer installed requirement was not linked conditionally: %#v", doc.Edges)
	}
	issues := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		issues[issue.Code] = true
	}
	if !issues["dependency_constraint_unverified"] || !issues["distribution_source_unavailable"] || !issues["composer_installed_files_unverified"] || issues["composer_installed_metadata_invalid"] {
		t.Fatalf("Composer coverage did not represent its limits: %#v", doc.Coverage.Issues)
	}
	archive := ociTestArchive(t, layout, "composer.oci.tar")
	archiveDoc, archiveOutput, archiveCode := ociTestScan(t, archive)
	if archiveCode != 0 || archiveDoc.Coverage.Packages != 2 || archiveDoc.Coverage.Edges != 3 {
		t.Fatalf("OCI Composer archive scan failed: code=%d output=%s coverage=%#v", archiveCode, archiveOutput, archiveDoc.Coverage)
	}
}

func TestOCIComposerCustomVendorDirectory(t *testing.T) {
	const manifestPath = "app/dependencies/composer/installed.json"
	const configPath = "app/composer.json"
	fixture := filepath.Join("..", "testdata", "oci", "composer-custom-vendor")
	installedData, err := os.ReadFile(filepath.Join(fixture, "dependencies", "composer", "installed.json"))
	if err != nil {
		t.Fatal(err)
	}
	configData, err := os.ReadFile(filepath.Join(fixture, "composer.json"))
	if err != nil {
		t.Fatal(err)
	}
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: configPath, data: configData}, {name: manifestPath, data: installedData}}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 {
		t.Fatalf("Composer custom vendor directory was missed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	byID := map[string]string{}
	for _, component := range doc.Components {
		byID[component.ID] = component.Name
		if component.Context != "registry="+manifestPath+";image=linux/amd64" || !strings.Contains(component.Evidence[0].InputPath, "!/"+manifestPath) {
			t.Fatalf("custom vendor metadata lost its scope: %#v", component)
		}
	}
	linked := false
	for _, edge := range doc.Edges {
		linked = linked || byID[edge.From] == "acme/alpha" && byID[edge.To] == "acme/beta" && edge.Kind == "depends_on" && edge.Condition == "composer_constraint=unverified"
	}
	if !linked {
		t.Fatalf("custom vendor package graph missing: %#v", doc.Edges)
	}

	removed := ociTestLayout(t)
	removedImage := ociTestImage(t, removed, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{{name: manifestPath, data: installedData}}},
		{entries: []ociTestEntry{{name: "app/.wh.dependencies"}}},
	})
	ociTestIndex(t, removed, removedImage)
	removedDoc, removedOutput, removedCode := ociTestScan(t, removed)
	if removedCode != 0 || removedDoc.Coverage.Packages != 0 {
		t.Fatalf("whiteouted custom vendor directory survived: code=%d output=%s coverage=%#v", removedCode, removedOutput, removedDoc.Coverage)
	}
}

func TestOCIComposerInstalledV1AndVirtualProvider(t *testing.T) {
	const manifestPath = "srv/project/vendor/composer/installed.json"
	metadata := []byte(`[
		{"name":"acme/alpha","version":"1.0.0","require":{"acme/beta":"*","psr/log-implementation":"*","php-http/discovery":"*","php":">=8.0","composer":"^2"}},
		{"name":"acme/beta","version":"2.0.1"},
		{"name":"acme/logger","version":"3.0.0","provide":{"psr/log-implementation":"1.0"},"require":{"psr/log-implementation":"*"}},
		{"name":"php-http/discovery","version":"1.0.0"}
	]`)
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: manifestPath, data: metadata}}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 4 || doc.Coverage.Edges != 7 {
		t.Fatalf("OCI Composer 1 inventory failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	names := map[string]string{}
	for _, component := range doc.Components {
		names[component.ID] = component.Name
		if component.Context != "registry="+manifestPath+";image=linux/amd64" || component.Evidence[0].Pointer == "" {
			t.Fatalf("Composer 1 context or evidence incorrect: %#v", component)
		}
	}
	direct := false
	virtual := false
	prefixed := false
	for _, edge := range doc.Edges {
		if edge.Kind == "depends_on" && edge.From == edge.To {
			t.Fatalf("Composer self-provided capability produced a self-edge: %#v", edge)
		}
		if names[edge.From] != "acme/alpha" || edge.Kind != "depends_on" {
			continue
		}
		direct = direct || names[edge.To] == "acme/beta" && edge.Condition == "" && edge.Evidence.Pointer == "/0/require/acme~1beta"
		virtual = virtual || names[edge.To] == "acme/logger" && edge.Condition == "provider=virtual" && edge.Evidence.Pointer == "/0/require/psr~1log-implementation"
		prefixed = prefixed || names[edge.To] == "php-http/discovery" && edge.Condition == "" && edge.Evidence.Pointer == "/0/require/php-http~1discovery"
	}
	if !direct || !virtual || !prefixed {
		t.Fatalf("Composer 1 direct or virtual dependency incorrect: %#v", doc.Edges)
	}
	virtualIssue := false
	for _, issue := range doc.Coverage.Issues {
		virtualIssue = virtualIssue || issue.Code == "composer_installed_virtual_provider_unverified" && issue.Name == "psr/log-implementation"
		if issue.Code == "unresolved_dependency" && (issue.Name == "php" || issue.Name == "composer") {
			t.Fatalf("Composer platform package was treated as missing distribution: %#v", issue)
		}
	}
	if !virtualIssue {
		t.Fatalf("virtual provider uncertainty was not reported: %#v", doc.Coverage.Issues)
	}
}

func TestOCIComposerInstalledInvalidAndUnscanned(t *testing.T) {
	const manifestPath = "app/vendor/composer/installed.json"
	for _, tc := range []struct {
		name  string
		file  ociTestEntry
		issue string
	}{
		{name: "escaping-name", file: ociTestEntry{name: manifestPath, data: []byte(`{"packages":[{"name":"acme/../../escape","version":"1.0.0"}]}`)}, issue: "composer_installed_metadata_invalid"},
		{name: "link", file: ociTestEntry{name: manifestPath, typeflag: tar.TypeSymlink, linkname: "../../other/installed.json"}, issue: "composer_installed_metadata_link_unresolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{tc.file}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || doc.Coverage.Packages != 0 || doc.Coverage.GraphState != "partial" {
				t.Fatalf("OCI invalid Composer scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
			}
			found := false
			for _, issue := range doc.Coverage.Issues {
				found = found || issue.Code == tc.issue
			}
			if !found {
				t.Fatalf("invalid Composer metadata was not reported: %#v", doc.Coverage.Issues)
			}
		})
	}
}

func TestOCIComposerMultipleVendorScopes(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "apps/one/vendor/composer/installed.json", data: []byte(`{"packages":[{"name":"acme/alpha","version":"1.0.0","require":{"acme/beta":"*"}}]}`)},
		{name: "apps/two/vendor/composer/installed.json", data: []byte(`{"packages":[{"name":"acme/beta","version":"1.0.0"}]}`)},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 || doc.Coverage.GraphState != "partial" {
		t.Fatalf("OCI Composer vendor scopes were conflated: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	missing := false
	for _, issue := range doc.Coverage.Issues {
		missing = missing || issue.Code == "unresolved_dependency" && issue.Name == "acme/beta" && issue.Scope == "acme/alpha"
	}
	if !missing {
		t.Fatalf("cross-vendor Composer dependency was treated as installed: %#v", doc.Coverage.Issues)
	}
}

func TestOCIComposerInstalledDoesNotExposeMetadataCredentials(t *testing.T) {
	layout := ociTestLayout(t)
	metadata := []byte(`{"packages":[{"name":"acme/alpha","version":"1.0.0","require":{"acme/beta":"https://user:secret@example.invalid/path"},"dist":{"url":"https://user:secret@example.invalid/archive.zip"}},{"name":"acme/beta","version":"2.0.0"}]}`)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "app/vendor/composer/installed.json", data: metadata}}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 {
		t.Fatalf("OCI Composer private metadata scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	serialized, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte("secret")) || bytes.Contains(serialized, []byte("example.invalid")) {
		t.Fatalf("Composer metadata credentials leaked into SBOM: %s", serialized)
	}
}
