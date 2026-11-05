package nuget

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

type lockfile struct {
	Version      int                                `json:"version"`
	Dependencies map[string]map[string]packageEntry `json:"dependencies"`
}

type packageEntry struct {
	Type         string            `json:"type"`
	Resolved     string            `json:"resolved"`
	ContentHash  string            `json:"contentHash"`
	Dependencies map[string]string `json:"dependencies"`
}

func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid packages.lock.json: %w", err)
	}
	if lock.Version < 1 || lock.Version > 3 || len(lock.Dependencies) == 0 {
		return model.Document{}, fmt.Errorf("unsupported NuGet lockfile version or missing targets")
	}
	doc := common.NewDocument(file, project, "nuget", data)
	multipleTargets := len(lock.Dependencies) > 1
	if multipleTargets {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: "multiple target frameworks"})
	}
	for target, packages := range lock.Dependencies {
		ids := map[string]string{}
		hasProjects := false
		for name, entry := range packages {
			if strings.EqualFold(entry.Type, "Project") {
				// A project reference is present in the restored graph, but the
				// lockfile does not identify a NuGet feed or, usually, a version.
				// Keep its dependencies without inventing a registry identity.
				ref := "nuget-project:" + common.ID(target+"|"+strings.ToLower(name))
				ids[strings.ToLower(name)] = ref
				ev := common.Evidence(file, "nuget-lock", "/dependencies/"+escapePointer(target)+"/"+escapePointer(name), data)
				doc.Components = append(doc.Components, model.Component{
					ID: ref, Kind: "application", Name: name, Version: entry.Resolved,
					Platform: target, Evidence: []model.Evidence{ev},
				})
				hasProjects = true
				continue
			}
			if entry.Resolved == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
				continue
			}
			ref := "nuget:" + common.ID(target+"|"+strings.ToLower(name)+"|"+entry.Resolved)
			ids[strings.ToLower(name)] = ref
			ev := common.Evidence(file, "nuget-lock", "/dependencies/"+escapePointer(target)+"/"+escapePointer(name), data)
			component := model.Component{
				ID: ref, Kind: "package", Name: name, Version: entry.Resolved, Platform: target,
				PURL: packageurl.NewPackageURL("nuget", "", name, entry.Resolved, nil, "").ToString(), PURLBasis: "ecosystem_inferred",
				Evidence: []model.Evidence{ev}, Hashes: common.Integrity("sha512-" + entry.ContentHash),
			}
			doc.Components = append(doc.Components, component)
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
		}
		if hasProjects {
			// The lockfile lists project nodes and their outgoing edges, but
			// does not say which projects the root references directly.
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies", Name: target, Scope: "project references"})
		}
		for name, entry := range packages {
			from := ids[strings.ToLower(name)]
			if from == "" {
				continue
			}
			if strings.EqualFold(entry.Type, "Direct") {
				addEdge(&doc, "root", from, "direct", target, multipleTargets, file, data)
			}
			for depName := range entry.Dependencies {
				to := ids[strings.ToLower(depName)]
				if to == "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: depName})
					continue
				}
				addEdge(&doc, from, to, "depends_on", target, multipleTargets, file, data)
			}
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func addEdge(doc *model.Document, from, to, kind, target string, conditional bool, file string, data []byte) {
	edge := model.Edge{From: from, To: to, Kind: kind, Evidence: common.Evidence(file, "nuget-lock", "/dependencies/"+escapePointer(target), data)}
	if conditional {
		edge.Condition = "tfm=" + target
	}
	doc.Edges = append(doc.Edges, edge)
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
