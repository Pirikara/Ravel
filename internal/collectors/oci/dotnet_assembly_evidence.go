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
		issues := map[string]bool{}
		addIssue := func(code string) {
			if !issues[code] {
				issues[code] = true
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: component.Name})
			}
		}
		for _, candidate := range candidates[identity] {
			state, found := assemblies[candidate.Path]
			if !found {
				continue
			}
			if len(users[candidate.Path]) > 1 {
				addIssue("dotnet_runtime_assembly_ambiguous")
				continue
			}
			if state.status != "" {
				addIssue("dotnet_runtime_assembly_" + state.status)
				continue
			}
			method := "managed-pe-runtime-asset-candidate"
			if candidate.RID != "" {
				method = "managed-pe-rid-asset-candidate"
				addIssue("dotnet_runtime_assembly_rid_unselected")
			}
			component.Evidence = append(component.Evidence, model.Evidence{
				Collector:   "dotnet-managed-assembly",
				InputPath:   "oci:" + state.layer + "!/" + candidate.Path,
				InputDigest: state.digest,
				Method:      method,
			})
			matched = true
		}
		if matched {
			addIssue("dotnet_runtime_assembly_identity_unverified")
		}
	}
}
