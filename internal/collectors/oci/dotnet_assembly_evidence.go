package oci

import (
	"strings"

	"ravel/internal/collectors/nuget"
	"ravel/internal/model"
)

func verifyDotnetRuntimeAssemblies(doc *model.Document, depsData []byte, manifestPath string, assemblies map[string]dotnetAssemblyState, users map[string]map[string]bool) {
	candidates := nuget.RuntimeAssemblyCandidates(depsData, manifestPath)
	for i := range doc.Components {
		component := &doc.Components[i]
		identity := strings.ToLower(component.Name + "/" + component.Version)
		matched := false
		for _, candidate := range candidates[identity] {
			state, found := assemblies[candidate]
			if !found {
				continue
			}
			if len(users[candidate]) > 1 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_runtime_assembly_ambiguous", Name: component.Name})
				continue
			}
			if state.status != "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_runtime_assembly_" + state.status, Name: component.Name})
				continue
			}
			component.Evidence = append(component.Evidence, model.Evidence{
				Collector:   "dotnet-managed-assembly",
				InputPath:   "oci:" + state.layer + "!/" + candidate,
				InputDigest: state.digest,
				Method:      "managed-pe-runtime-asset-candidate",
			})
			matched = true
		}
		if matched {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_runtime_assembly_identity_unverified", Name: component.Name})
		}
	}
}
