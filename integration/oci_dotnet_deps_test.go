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

func TestOCIDotnetDepsGeneratedRuntimeGraph(t *testing.T) {
	const manifestPath = "app/app.deps.json"
	data, err := os.ReadFile(filepath.Join("..", "testdata", "oci", "dotnet-deps-v10", "app.deps.json"))
	if err != nil {
		t.Fatal(err)
	}
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{{name: manifestPath, data: []byte(`{"runtimeTarget":{"name":"old"},"targets":{"old":{}},"libraries":{}}`)}}},
		{gzip: true, entries: []ociTestEntry{{name: "app/.wh.app.deps.json"}, {name: manifestPath, data: data}}},
	})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 8 || doc.Coverage.Edges != 10 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("generated .NET runtime graph failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	byName := map[string]string{}
	for _, component := range doc.Components {
		byName[component.ID] = component.Name
		if component.Context != "manifest="+manifestPath+";image=linux/amd64" || component.Platform != ".NETCoreApp,Version=v10.0" || component.Evidence[0].Collector != "nuget-deps" || !strings.Contains(component.Evidence[0].InputPath, "!/"+manifestPath) || component.PURL != "" {
			t.Fatalf(".NET manifest identity or evidence incorrect: %#v", component)
		}
		if strings.HasPrefix(component.Name, "Microsoft.Extensions.") && (component.Kind != "package" || len(component.Hashes) != 1 || component.Hashes[0].Alg != "SHA-512") {
			t.Fatalf("NuGet package hash or kind incorrect: %#v", component)
		}
	}
	root := false
	project := false
	transitive := false
	for _, edge := range doc.Edges {
		root = root || edge.From == "root" && byName[edge.To] == "app" && edge.Kind == "installed"
		project = project || byName[edge.From] == "app" && byName[edge.To] == "lib" && edge.Kind == "depends_on"
		transitive = transitive || byName[edge.From] == "Microsoft.Extensions.Logging" && byName[edge.To] == "Microsoft.Extensions.Options" && edge.Kind == "depends_on" && edge.Condition == "" && strings.HasSuffix(edge.Evidence.Pointer, "/dependencies/Microsoft.Extensions.Options")
	}
	if !root || !project || !transitive {
		t.Fatalf(".NET project or package graph incomplete: %#v", doc.Edges)
	}
	issues := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		issues[issue.Code] = true
	}
	if !issues["dotnet_runtime_assets_unverified"] || !issues["distribution_source_unavailable"] || issues["dotnet_deps_metadata_invalid"] {
		t.Fatalf(".NET runtime scope limits missing: %#v", doc.Coverage.Issues)
	}
	archive := ociTestArchive(t, layout, "dotnet.oci.tar")
	archiveDoc, archiveOutput, archiveCode := ociTestScan(t, archive)
	if archiveCode != 0 || archiveDoc.Coverage.Packages != 8 || archiveDoc.Coverage.Edges != 10 {
		t.Fatalf(".NET OCI archive scan failed: code=%d output=%s coverage=%#v", archiveCode, archiveOutput, archiveDoc.Coverage)
	}
}

func TestOCIDotnetDepsOmitsNonRuntimeLibraries(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "oci", "dotnet-deps-v8", "legacy.deps.json"))
	if err != nil {
		t.Fatal(err)
	}
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "app/legacy.deps.json", data: data}}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 4 || doc.Coverage.Edges != 4 {
		t.Fatalf("non-runtime libraries were counted: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	byID := map[string]string{}
	for _, component := range doc.Components {
		byID[component.ID] = component.Name
		if component.Name == "Build.Analyzer" || component.Name == "Unused.Meta" {
			t.Fatalf("library without a path to runtime assets was counted: %#v", component)
		}
	}
	bridge := false
	for _, edge := range doc.Edges {
		bridge = bridge || byID[edge.From] == "Bridge.Meta" && byID[edge.To] == "Runtime.Leaf" && edge.Kind == "depends_on"
	}
	if !bridge {
		t.Fatalf("runtime dependency bridge was dropped: %#v", doc.Edges)
	}
	issues := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		issues[issue.Code+":"+issue.Name] = true
	}
	if !issues["dotnet_non_runtime_library_omitted:Build.Analyzer"] || !issues["dotnet_non_runtime_library_omitted:Unused.Meta"] || !issues["dotnet_manifest_only_library:Bridge.Meta"] || issues["unresolved_dependency:Build.Analyzer"] {
		t.Fatalf(".NET runtime selection was not explained: %#v", doc.Coverage.Issues)
	}
}

func TestOCIDotnetDepsWhiteoutAndManifestScopes(t *testing.T) {
	const template = `{"runtimeTarget":{"name":"net10.0"},"targets":{"net10.0":{"app/1.0.0":{"dependencies":{"Acme.Core":"2.0.0"},"runtime":{"app.dll":{}}},"Acme.Core/2.0.0":{"runtime":{"core.dll":{}}}}},"libraries":{"app/1.0.0":{"type":"project"},"Acme.Core/2.0.0":{"type":"package"}}}`
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{{name: "stale/app.deps.json", data: []byte(template)}, {name: "one/app.deps.json", data: []byte(template)}}},
		{entries: []ociTestEntry{{name: "stale/.wh.app.deps.json"}, {name: "two/app.deps.json", data: []byte(template)}}},
	})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 4 || doc.Coverage.Edges != 4 {
		t.Fatalf(".NET manifests crossed scopes or ignored whiteout: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	for _, component := range doc.Components {
		if strings.Contains(component.Context, "stale/") {
			t.Fatalf("whiteouted .NET manifest survived: %#v", component)
		}
	}
}

func TestOCIDotnetDepsInvalidAndUnscanned(t *testing.T) {
	const manifestPath = "app/app.deps.json"
	for _, tc := range []struct {
		name  string
		file  ociTestEntry
		issue string
	}{
		{name: "missing-runtime-target", file: ociTestEntry{name: manifestPath, data: []byte(`{"runtimeTarget":{"name":"net10.0"},"targets":{},"libraries":{}}`)}, issue: "dotnet_deps_metadata_invalid"},
		{name: "link", file: ociTestEntry{name: manifestPath, typeflag: tar.TypeSymlink, linkname: "../other/app.deps.json"}, issue: "dotnet_deps_metadata_link_unresolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{tc.file}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || doc.Coverage.Packages != 0 || doc.Coverage.GraphState != "partial" {
				t.Fatalf("invalid .NET OCI scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
			}
			found := false
			for _, issue := range doc.Coverage.Issues {
				found = found || issue.Code == tc.issue
			}
			if !found {
				t.Fatalf("invalid .NET manifest was not reported: %#v", doc.Coverage.Issues)
			}
		})
	}
}

func TestOCIDotnetDepsDoesNotExposeUntrustedMetadata(t *testing.T) {
	manifest := []byte(`{"runtimeTarget":{"name":"net10.0"},"targets":{"net10.0":{"app/1.0.0":{"dependencies":{"Acme.Core":"2.0.0"}},"Acme.Core/2.0.0":{"runtime":{"core.dll":{}}}}},"libraries":{"app/1.0.0":{"type":"project"},"Acme.Core/2.0.0":{"type":"package","path":"https://user:secret@example.invalid/pkg","sha512":"not-a-hash"}}}`)
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "app/app.deps.json", data: manifest}}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 {
		t.Fatalf(".NET metadata with untrusted path failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	serialized, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte("secret")) || bytes.Contains(serialized, []byte("example.invalid")) {
		t.Fatalf(".NET manifest metadata leaked into SBOM: %s", serialized)
	}
	found := false
	for _, issue := range doc.Coverage.Issues {
		found = found || issue.Code == "dotnet_package_hash_invalid" && issue.Name == "Acme.Core"
	}
	if !found {
		t.Fatalf("invalid package hash was accepted: %#v", doc.Coverage.Issues)
	}
}
