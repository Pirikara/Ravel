package integration_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dotnetRIDFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "oci", "dotnet-rid-assembly", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOCIDotnetRIDSpecificAssemblyEvidence(t *testing.T) {
	const linux = "app/runtimes/linux-x64/lib/net10.0/Acme.Runtime.dll"
	const macOS = "app/runtimes/osx-arm64/lib/net10.0/Acme.Runtime.dll"
	deps := dotnetRIDFixture(t, "app.deps.json")
	linuxDLL := dotnetRIDFixture(t, "runtimes/linux-x64/lib/net10.0/Acme.Runtime.dll")
	macDLL := dotnetRIDFixture(t, "runtimes/osx-arm64/lib/net10.0/Acme.Runtime.dll")
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "app/app.deps.json", data: deps},
		{name: "app/app.dll", data: dotnetRIDFixture(t, "app.dll")},
		{name: linux, data: linuxDLL},
		{name: macOS, data: macDLL},
	}}})
	ociTestIndex(t, layout, image)
	for _, input := range []string{layout, ociTestArchive(t, layout, "dotnet-rid.oci.tar")} {
		doc, output, code := ociTestScan(t, input)
		if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 {
			t.Fatalf("RID-specific .NET scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
		}
		component := dotnetComponent(t, doc, "Acme.RidRuntime")
		if component.Version != "2.3.4" || len(component.Evidence) != 3 || component.PURL != "pkg:nuget/Acme.RidRuntime@2.3.4" || component.PURLBasis != "ecosystem_inferred" {
			t.Fatalf("RID-specific package identity or evidence incorrect: %#v", component)
		}
		if app := dotnetComponent(t, doc, "app"); len(app.Evidence) != 2 || app.Evidence[1].Method != "managed-pe-runtime-asset-candidate" {
			t.Fatalf("root assembly evidence incorrect: %#v", app)
		}
		hash := sha256.Sum256(linuxDLL)
		paths := map[string]bool{}
		for _, evidence := range component.Evidence[1:] {
			if evidence.Collector != "dotnet-managed-assembly" || evidence.Method != "managed-pe-rid-asset-candidate" || evidence.InputDigest != "sha256:"+hex.EncodeToString(hash[:]) {
				t.Fatalf("RID-specific assembly file evidence incorrect: %#v", evidence)
			}
			paths[evidence.InputPath] = true
		}
		foundLinux, foundMac := false, false
		for location := range paths {
			foundLinux = foundLinux || strings.HasSuffix(location, "!/"+linux)
			foundMac = foundMac || strings.HasSuffix(location, "!/"+macOS)
		}
		if !foundLinux || !foundMac || !dotnetIssue(doc, "dotnet_runtime_assembly_rid_unselected") || !dotnetIssue(doc, "dotnet_runtime_assembly_identity_unverified") {
			t.Fatalf("RID-specific file paths or selection uncertainty missing: paths=%#v issues=%#v", paths, doc.Coverage.Issues)
		}
	}
}

func TestOCIDotnetRIDSpecificAssemblyWhiteout(t *testing.T) {
	const linux = "app/runtimes/linux-x64/lib/net10.0/Acme.Runtime.dll"
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{
			{name: "app/app.deps.json", data: dotnetRIDFixture(t, "app.deps.json")},
			{name: linux, data: dotnetRIDFixture(t, "runtimes/linux-x64/lib/net10.0/Acme.Runtime.dll")},
		}},
		{entries: []ociTestEntry{{name: "app/runtimes/linux-x64/lib/net10.0/.wh.Acme.Runtime.dll"}}},
	})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || len(dotnetComponent(t, doc, "Acme.RidRuntime").Evidence) != 1 {
		t.Fatalf("RID-specific whiteout retained stale DLL: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
}
