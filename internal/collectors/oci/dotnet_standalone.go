package oci

import (
	"path"
	"sort"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

// collectStandaloneDotnetAssemblies reports managed files that no valid
// .deps.json runtime asset claims. VERSIONINFO identifies the assembly file,
// but does not establish a NuGet package or its dependency graph.
func collectStandaloneDotnetAssemblies(doc *model.Document, assemblies map[string]dotnetAssemblyState, users map[string]map[string]bool) {
	names := make([]string, 0, len(assemblies))
	for name := range assemblies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, filename := range names {
		state := assemblies[filename]
		if len(users[filename]) != 0 || state.status != "" {
			continue
		}
		// Satellite assemblies carry localized resources for an existing
		// assembly; a file without its own identity is not another package.
		if strings.HasSuffix(strings.ToLower(path.Base(filename)), ".resources.dll") {
			continue
		}
		if state.name == "" || state.version == "" || path.Base(filename) != state.name+".dll" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_standalone_assembly_identity_unverified", Name: filename})
			continue
		}
		source := "oci:" + state.layer + "!/" + filename
		evidence := model.Evidence{Collector: "dotnet-managed-assembly", InputPath: source, InputDigest: state.digest, Method: "pe-version-resource"}
		id := "dotnet-assembly:" + common.ID(source+"\x00"+state.version)
		doc.Components = append(doc.Components, model.Component{
			ID: id, Kind: "package", Name: state.name, Version: state.version,
			Context:  "location=/" + filename + ";assembly=managed-pe",
			Hashes:   []model.Hash{{Alg: "SHA-256", Content: strings.TrimPrefix(state.digest, "sha256:")}},
			Evidence: []model.Evidence{evidence},
		})
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
		doc.Coverage.Issues = append(doc.Coverage.Issues,
			model.Issue{Code: "dotnet_standalone_assembly_graph_unavailable", Name: filename},
			model.Issue{Code: "dotnet_standalone_assembly_origin_unavailable", Name: filename})
	}
}
