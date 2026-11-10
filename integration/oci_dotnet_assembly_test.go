package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func dotnetAssemblyFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "oci", "dotnet-managed-assembly", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func dotnetComponent(t *testing.T, doc model.Document, name string) model.Component {
	t.Helper()
	for _, component := range doc.Components {
		if component.Name == name {
			return component
		}
	}
	t.Fatalf(".NET component %q absent: %#v", name, doc.Components)
	return model.Component{}
}

func dotnetIssue(doc model.Document, code string) bool {
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func TestOCIDotnetManagedAssemblyEvidence(t *testing.T) {
	deps := dotnetAssemblyFixture(t, "app.deps.json")
	packageDLL := dotnetAssemblyFixture(t, "Acme.Runtime.dll")
	appDLL := dotnetAssemblyFixture(t, "app.dll")
	layers := []ociTestLayer{
		{entries: []ociTestEntry{{name: "app/app.deps.json", data: deps}, {name: "app/Acme.Runtime.dll", data: []byte("stale native file")}}},
		{gzip: true, entries: []ociTestEntry{{name: "app/Acme.Runtime.dll", data: packageDLL}, {name: "app/app.dll", data: appDLL}}},
	}
	layout := ociTestLayout(t)
	ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", layers))
	for _, input := range []string{layout, ociTestArchive(t, layout, "dotnet-assembly.oci.tar")} {
		doc, output, code := ociTestScan(t, input)
		if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 {
			t.Fatalf(".NET assembly scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
		}
		for _, tc := range []struct {
			component, filename string
			data                []byte
		}{{"Acme.Runtime", "Acme.Runtime.dll", packageDLL}, {"app", "app.dll", appDLL}} {
			component := dotnetComponent(t, doc, tc.component)
			if len(component.Evidence) != 2 || component.Evidence[0].Collector != "nuget-deps" || component.Evidence[1].Collector != "dotnet-managed-assembly" {
				t.Fatalf(".NET assembly candidate evidence incorrect: %#v", component)
			}
			if tc.component == "Acme.Runtime" && (component.PURL != "pkg:nuget/Acme.Runtime@1.2.3" || component.PURLBasis != "ecosystem_inferred") || tc.component == "app" && component.PURL != "" {
				t.Fatalf(".NET assembly package identity incorrect: %#v", component)
			}
			hash := sha256.Sum256(tc.data)
			evidence := component.Evidence[1]
			if evidence.InputDigest != "sha256:"+hex.EncodeToString(hash[:]) || !strings.HasSuffix(evidence.InputPath, "!/app/"+tc.filename) || evidence.Method != "managed-pe-runtime-asset-candidate" {
				t.Fatalf(".NET assembly file evidence incorrect: %#v", evidence)
			}
		}
		if !dotnetIssue(doc, "dotnet_runtime_assembly_identity_unverified") || !dotnetIssue(doc, "dotnet_runtime_assets_unverified") || doc.Coverage.GraphState != "partial" {
			t.Fatalf(".NET assembly limits missing: %#v", doc.Coverage)
		}
	}
}

func TestOCIDotnetStandaloneAssembly(t *testing.T) {
	assembly := dotnetAssemblyFixture(t, "Acme.Runtime.dll")
	for _, tc := range []struct {
		name, filename string
		layers         []ociTestLayer
		wantVersion    string
		wantIssue      string
	}{
		{"versioned", "app/plugins/Acme.Runtime.dll", []ociTestLayer{{entries: []ociTestEntry{{name: "app/plugins/Acme.Runtime.dll", data: assembly}}}}, "1.2.3", ""},
		{"renamed", "app/plugins/Renamed.dll", []ociTestLayer{{entries: []ociTestEntry{{name: "app/plugins/Renamed.dll", data: assembly}}}}, "", "dotnet_standalone_assembly_identity_unverified"},
		{"satellite", "app/plugins/Acme.Runtime.resources.dll", []ociTestLayer{{entries: []ociTestEntry{{name: "app/plugins/Acme.Runtime.resources.dll", data: assembly}}}}, "", ""},
		{"whiteout", "app/plugins/Acme.Runtime.dll", []ociTestLayer{
			{entries: []ociTestEntry{{name: "app/plugins/Acme.Runtime.dll", data: assembly}}},
			{entries: []ociTestEntry{{name: "app/plugins/.wh.Acme.Runtime.dll"}}},
		}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", tc.layers))
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("standalone assembly scan failed: code=%d output=%s", code, output)
			}
			if doc.Coverage.Packages != 0 && tc.wantVersion == "" || doc.Coverage.Packages != 1 && tc.wantVersion != "" {
				t.Fatalf("standalone assembly component count incorrect: %#v", doc.Coverage)
			}
			if tc.wantIssue != "" && !dotnetIssue(doc, tc.wantIssue) {
				t.Fatalf("standalone assembly issue absent: %#v", doc.Coverage.Issues)
			}
			if tc.name == "satellite" && dotnetIssue(doc, "dotnet_standalone_assembly_identity_unverified") {
				t.Fatalf("localized resource DLL was treated as a separate package: %#v", doc.Coverage.Issues)
			}
			if tc.wantVersion == "" {
				return
			}
			component := dotnetComponent(t, doc, "Acme.Runtime")
			hash := sha256.Sum256(assembly)
			if component.Version != tc.wantVersion || component.PURL != "" || len(component.Hashes) != 1 || component.Hashes[0].Content != hex.EncodeToString(hash[:]) || component.Evidence[0].Method != "pe-version-resource" || !strings.HasSuffix(component.Evidence[0].InputPath, "!/"+tc.filename) || !dotnetIssue(doc, "dotnet_standalone_assembly_graph_unavailable") || !dotnetIssue(doc, "dotnet_standalone_assembly_origin_unavailable") {
				t.Fatalf("standalone assembly identity or limits incorrect: %#v %#v", component, doc.Coverage)
			}
		})
	}
}

func TestOCIDotnetManagedAssemblySizeBoundary(t *testing.T) {
	deps := dotnetAssemblyFixture(t, "app.deps.json")
	base := dotnetAssemblyFixture(t, "Acme.Runtime.dll")
	for _, test := range []struct {
		name         string
		size         int
		wantEvidence bool
	}{
		{name: "official_runtime_sized", size: 17080104, wantEvidence: true},
		{name: "above_limit", size: (20 << 20) + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			assembly := make([]byte, test.size)
			copy(assembly, base)
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
				{name: "app/app.deps.json", data: deps},
				{name: "app/Acme.Runtime.dll", data: assembly},
			}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("large .NET assembly scan failed: code=%d output=%s", code, output)
			}
			component := dotnetComponent(t, doc, "Acme.Runtime")
			if (len(component.Evidence) == 2) != test.wantEvidence || dotnetIssue(doc, "dotnet_runtime_assembly_oversized") == test.wantEvidence {
				t.Fatalf("large .NET assembly limit incorrect: evidence=%#v issues=%#v", component.Evidence, doc.Coverage.Issues)
			}
			if test.wantEvidence {
				hash := sha256.Sum256(assembly)
				if component.Evidence[1].InputDigest != "sha256:"+hex.EncodeToString(hash[:]) {
					t.Fatalf("large .NET assembly digest incorrect: %#v", component.Evidence[1])
				}
			}
		})
	}
}

func TestOCIDotnetManagedAssemblyOverlay(t *testing.T) {
	deps := dotnetAssemblyFixture(t, "app.deps.json")
	packageDLL := dotnetAssemblyFixture(t, "Acme.Runtime.dll")
	for _, tc := range []struct {
		name, issue string
		entry       ociTestEntry
	}{
		{"whiteout", "", ociTestEntry{name: "app/.wh.Acme.Runtime.dll"}},
		{"native-replacement", "dotnet_runtime_assembly_invalid", ociTestEntry{name: "app/Acme.Runtime.dll", data: []byte("not a managed PE")}},
		{"symlink-replacement", "dotnet_runtime_assembly_link_unresolved", ociTestEntry{name: "app/Acme.Runtime.dll", typeflag: tar.TypeSymlink, linkname: "elsewhere.dll"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
				{entries: []ociTestEntry{{name: "app/app.deps.json", data: deps}, {name: "app/Acme.Runtime.dll", data: packageDLL}}},
				{entries: []ociTestEntry{tc.entry}},
			})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || doc.Coverage.Packages != 2 || len(dotnetComponent(t, doc, "Acme.Runtime").Evidence) != 1 {
				t.Fatalf(".NET overlay retained stale DLL: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
			}
			if tc.issue != "" && !dotnetIssue(doc, tc.issue) {
				t.Fatalf(".NET replacement issue %q absent: %#v", tc.issue, doc.Coverage.Issues)
			}
		})
	}
}

func TestOCIDotnetManagedAssemblyAmbiguousAsset(t *testing.T) {
	deps := []byte(`{"runtimeTarget":{"name":"net10.0"},"targets":{"net10.0":{"app/1.0.0":{"runtime":{"app.dll":{}}},"Acme.Runtime/1.2.3":{"runtime":{"lib/net10.0/Acme.Runtime.dll":{}}},"Other.Package/2.0.0":{"runtime":{"lib/net10.0/Acme.Runtime.dll":{}}}}},"libraries":{"app/1.0.0":{"type":"project"},"Acme.Runtime/1.2.3":{"type":"package"},"Other.Package/2.0.0":{"type":"package"}}}`)
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "app/app.deps.json", data: deps},
		{name: "app/Acme.Runtime.dll", data: dotnetAssemblyFixture(t, "Acme.Runtime.dll")},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 3 || !dotnetIssue(doc, "dotnet_runtime_assembly_ambiguous") {
		t.Fatalf("ambiguous .NET asset scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	for _, name := range []string{"Acme.Runtime", "Other.Package"} {
		if component := dotnetComponent(t, doc, name); len(component.Evidence) != 1 {
			t.Fatalf("ambiguous DLL was attributed to %s: %#v", name, component)
		}
	}
}

func TestOCIDotnetManagedAssemblyIgnoresInvalidManifestClaims(t *testing.T) {
	// A malformed second deps file must not suppress a valid manifest's
	// association just by naming the same DLL.
	invalid := []byte(`{"runtimeTarget":{"name":"net10.0"},"targets":{"net10.0":{"Other.Package/2.0.0":{"runtime":{"Acme.Runtime.dll":{}}}}},"libraries":{}}`)
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "app/app.deps.json", data: dotnetAssemblyFixture(t, "app.deps.json")},
		{name: "app/bad.deps.json", data: invalid},
		{name: "app/Acme.Runtime.dll", data: dotnetAssemblyFixture(t, "Acme.Runtime.dll")},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || len(dotnetComponent(t, doc, "Acme.Runtime").Evidence) != 2 || !dotnetIssue(doc, "dotnet_deps_metadata_invalid") {
		t.Fatalf("invalid .NET manifest influenced file evidence: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
}

func TestOCIDotnetManagedAssemblyLastEntryInLayerWins(t *testing.T) {
	deps := dotnetAssemblyFixture(t, "app.deps.json")
	managed := dotnetAssemblyFixture(t, "Acme.Runtime.dll")
	for _, tc := range []struct {
		name string
		last []byte
		want int
	}{
		{"managed-last", managed, 2},
		{"native-last", []byte("native replacement"), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := managed
			if tc.want == 2 {
				first = []byte("native replacement")
			}
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
				{name: "app/app.deps.json", data: deps},
				{name: "app/Acme.Runtime.dll", data: first},
				{name: "app/Acme.Runtime.dll", data: tc.last},
			}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(dotnetComponent(t, doc, "Acme.Runtime").Evidence) != tc.want {
				t.Fatalf(".NET same-layer replacement failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
			}
		})
	}
}
