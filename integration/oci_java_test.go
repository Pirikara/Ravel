package integration_test

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func javaFixtureArchive(t *testing.T, directory, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", directory, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOCIJavaArchivesFinalLayerAndEvidence(t *testing.T) {
	layout := ociTestLayout(t)
	basic := javaFixtureArchive(t, "java-jar-basic", "sample.jar")
	boot := javaFixtureArchive(t, "java-boot", "boot.jar")
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{
			{name: "opt/app/old.jar", data: basic},
			{name: "opt/app/boot.jar", data: boot},
		}},
		{entries: []ociTestEntry{
			{name: "opt/app/.wh.old.jar"},
			{name: "opt/app/lib/a.jar", data: basic},
			{name: "opt/app/lib/b.jar", data: basic},
			{name: "opt/app/broken.jar", data: []byte("not a zip archive")},
			{name: "opt/app/link.jar", typeflag: tar.TypeSymlink, linkname: "lib/a.jar"},
		}},
	})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 5 || doc.Coverage.Edges != 5 || doc.Coverage.Manager != "oci" {
		t.Fatalf("OCI Java inventory incorrect: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	ids := map[string]bool{}
	for _, component := range doc.Components {
		if ids[component.ID] || len(component.Hashes) != 1 || component.Hashes[0].Alg != "SHA-256" || !strings.Contains(component.Context, "image=linux/amd64") {
			t.Fatalf("duplicate or incomplete Java component: %#v", component)
		}
		ids[component.ID] = true
		if !strings.HasPrefix(component.Evidence[0].InputPath, "oci:sha256:") || strings.Contains(component.Evidence[0].InputPath, "old.jar") {
			t.Fatalf("whiteouted archive or wrong evidence: %#v", component.Evidence[0])
		}
	}
	if len(doc.Development) != 4 {
		t.Fatalf("embedded Java development repositories missing: %#v", doc.Development)
	}
	issues := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		issues[issue.Code] = true
	}
	if !issues["java_installed_archive_invalid"] || !issues["java_installed_archive_link_unresolved"] {
		t.Fatalf("invalid and linked Java archives were not reported: %#v", doc.Coverage.Issues)
	}
}

func TestOCIJavaArchiveReplacement(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{{name: "app/app.jar", data: javaFixtureArchive(t, "java-jar-basic", "sample.jar")}}},
		{entries: []ociTestEntry{{name: "app/app.jar", data: javaFixtureArchive(t, "java-jar-connection", "connection.jar")}}},
	})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/example/connection-only.git" {
		t.Fatalf("replaced Java archive remained in OCI inventory: code=%d output=%s doc=%#v", code, output, doc)
	}
}

func TestOCIJavaArchiveUnderSameLayerSymlinkRejected(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "app", typeflag: tar.TypeSymlink, linkname: "/outside"},
		{name: "app/sample.jar", data: javaFixtureArchive(t, "java-jar-basic", "sample.jar")},
	}}})
	ociTestIndex(t, layout, image)
	_, output, code := ociTestScan(t, layout)
	if code != 1 || !strings.Contains(output, "non-directory entry") {
		t.Fatalf("Java archive beneath same-layer symlink was accepted: code=%d output=%s", code, output)
	}
}
