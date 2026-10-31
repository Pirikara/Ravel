package nuget

import (
	"strings"
	"testing"
)

func TestDepsManifestPath(t *testing.T) {
	for _, name := range []string{"app.deps.json", "app/app.deps.json", "usr/share/dotnet/shared/Microsoft.NETCore.App/10.0.1/Microsoft.NETCore.App.deps.json"} {
		if !IsDepsManifestPath(name) {
			t.Fatalf("valid .NET deps path rejected: %s", name)
		}
	}
	for _, name := range []string{".deps.json", "../app.deps.json", "/app.deps.json", "app/../app.deps.json", "app/secret:user.deps.json", "app.deps.json.backup"} {
		if IsDepsManifestPath(name) {
			t.Fatalf("invalid .NET deps path accepted: %s", name)
		}
	}
}

func TestDepsRuntimeTargetSelection(t *testing.T) {
	data := []byte(`{"runtimeTarget":{"name":"net10.0/linux-x64"},"targets":{"net10.0":{"Build.Only/1.0.0":{"compile":{"Build.Only.dll":{}}}},"net10.0/linux-x64":{"App/1.0.0":{"dependencies":{"Runtime.Pack":"2.0.0"}},"Runtime.Pack/2.0.0":{"runtime":{"Runtime.Pack.dll":{}}}}},"libraries":{"Build.Only/1.0.0":{"type":"package"},"App/1.0.0":{"type":"project"},"Runtime.Pack/2.0.0":{"type":"runtimepack"}}}`)
	doc, err := CollectInstalledDeps(data, "oci:sha256:abc!/app/App.deps.json", "test", "app/App.deps.json")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 || doc.Coverage.GraphState != "partial" {
		t.Fatalf("selected runtime target has wrong graph: %#v", doc.Coverage)
	}
	byName := map[string]string{}
	for _, component := range doc.Components {
		byName[component.ID] = component.Name
		if component.Name == "Build.Only" {
			t.Fatal("compile-only target entered runtime SBOM")
		}
	}
	root := false
	dependency := false
	for _, edge := range doc.Edges {
		root = root || edge.From == "root" && byName[edge.To] == "App"
		dependency = dependency || byName[edge.From] == "App" && byName[edge.To] == "Runtime.Pack"
	}
	if !root || !dependency {
		t.Fatalf("project root or runtime dependency missing: %#v", doc.Edges)
	}
	found := false
	for _, issue := range doc.Coverage.Issues {
		found = found || issue.Code == "dotnet_runtimepack_identity_unverified" && issue.Name == "Runtime.Pack"
	}
	if !found {
		t.Fatalf("runtimepack uncertainty missing: %#v", doc.Coverage.Issues)
	}
}

func TestDepsMalformedAndAmbiguous(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{"missing-target", `{"runtimeTarget":{"name":"net10.0"},"targets":{},"libraries":{}}`},
		{"missing-library", `{"runtimeTarget":{"name":"net10.0"},"targets":{"net10.0":{"Acme.Core/1.0.0":{}}},"libraries":{}}`},
		{"duplicate-case", `{"runtimeTarget":{"name":"net10.0"},"targets":{"net10.0":{"Acme.Core/1.0.0":{},"acme.core/1.0.0":{}}},"libraries":{"Acme.Core/1.0.0":{"type":"package"},"acme.core/1.0.0":{"type":"package"}}}`},
		{"unsafe-name", `{"runtimeTarget":{"name":"net10.0"},"targets":{"net10.0":{"https://secret@example.invalid/1.0.0":{}}},"libraries":{"https://secret@example.invalid/1.0.0":{"type":"package"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CollectInstalledDeps([]byte(tc.data), "source", "test", "app.deps.json"); err == nil {
				t.Fatal("invalid .NET dependency manifest was accepted")
			}
		})
	}
}

func TestDepsInvalidDependencyDoesNotLeak(t *testing.T) {
	data := []byte(`{"runtimeTarget":{"name":"net10.0"},"targets":{"net10.0":{"App/1.0.0":{"dependencies":{"https://user:secret@example.invalid/pkg":"1.0.0"}},"Core/1.0.0":{"runtime":{"Core.dll":{}}}}},"libraries":{"App/1.0.0":{"type":"project"},"Core/1.0.0":{"type":"package"}}}`)
	doc, err := CollectInstalledDeps(data, "source", "test", "App.deps.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range doc.Coverage.Issues {
		if strings.Contains(issue.Name, "secret") || strings.Contains(issue.Scope, "secret") {
			t.Fatalf("untrusted dependency leaked: %#v", issue)
		}
	}
}
