package nuget

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

type assetsFile struct {
	Version   int                        `json:"version"`
	Targets   map[string]json.RawMessage `json:"targets"`
	Libraries map[string]struct {
		SHA512 string `json:"sha512"`
	} `json:"libraries"`
	ProjectFileDependencyGroups map[string][]string `json:"projectFileDependencyGroups"`
	Project                     struct {
		Frameworks map[string]struct {
			Dependencies map[string]json.RawMessage `json:"dependencies"`
		} `json:"frameworks"`
	} `json:"project"`
}

type assetsEntry struct {
	Type         string            `json:"type"`
	Dependencies map[string]string `json:"dependencies"`
}

// CollectAssets reads the graph produced by NuGet restore. Restore sources in
// this file are configuration, not proof of which feed supplied each package.
func CollectAssets(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var assets assetsFile
	if err := json.Unmarshal(data, &assets); err != nil {
		return model.Document{}, fmt.Errorf("invalid project.assets.json: %w", err)
	}
	if (assets.Version != 3 && assets.Version != 4) || len(assets.Targets) == 0 {
		return model.Document{}, fmt.Errorf("unsupported project.assets.json version or missing targets")
	}
	doc := common.NewDocument(file, project, "nuget", data)
	multi := len(assets.Targets) > 1
	if multi {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: "multiple target frameworks"})
	}
	for target, raw := range assets.Targets {
		var packages map[string]json.RawMessage
		if err := json.Unmarshal(raw, &packages); err != nil {
			return model.Document{}, fmt.Errorf("invalid assets target %s: %w", target, err)
		}
		byName := map[string][]string{}
		entries := map[string]assetsEntry{}
		for key, entryRaw := range packages {
			if strings.HasPrefix(key, "@") {
				continue
			}
			var entry assetsEntry
			if err := json.Unmarshal(entryRaw, &entry); err != nil {
				return model.Document{}, fmt.Errorf("invalid assets package %s: %w", key, err)
			}
			if entry.Type != "package" {
				continue
			}
			name, version, ok := strings.Cut(key, "/")
			if !ok || name == "" || version == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: key})
				continue
			}
			ref := "nuget:" + common.ID(target+"|"+strings.ToLower(key))
			ev := common.Evidence(file, "nuget-assets", "/targets/"+escapePointer(target)+"/"+escapePointer(key), data)
			component := model.Component{ID: ref, Kind: "package", Name: name, Version: version, Platform: target, Evidence: []model.Evidence{ev}}
			if lib, ok := assets.Libraries[key]; ok {
				hash := lib.SHA512
				if hash != "" && !strings.HasPrefix(hash, "sha512-") {
					hash = "sha512-" + hash
				}
				component.Hashes = common.Integrity(hash)
			}
			doc.Components = append(doc.Components, component)
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
			byName[strings.ToLower(name)] = append(byName[strings.ToLower(name)], ref)
			entries[key] = entry
		}
		resolve := func(name string) string {
			refs := byName[strings.ToLower(name)]
			if len(refs) == 1 {
				return refs[0]
			}
			code := "unresolved_dependency"
			if len(refs) > 1 {
				code = "ambiguous_dependency"
			}
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name})
			return ""
		}
		for key, entry := range entries {
			name, _, _ := strings.Cut(key, "/")
			from := resolve(name)
			if from == "" {
				continue
			}
			for dep := range entry.Dependencies {
				to := resolve(dep)
				if to != "" {
					addAssetsEdge(&doc, from, to, "depends_on", target, multi, file, data)
				}
			}
		}
		group, found := assets.ProjectFileDependencyGroups[target]
		if !found {
			group, found = assets.ProjectFileDependencyGroups[strings.SplitN(target, "/", 2)[0]]
		}
		if found {
			for _, item := range group {
				name := strings.Fields(item)
				if len(name) == 0 {
					continue
				}
				to := resolve(name[0])
				if to != "" {
					addAssetsEdge(&doc, "root", to, "direct", target, multi, file, data)
				}
			}
		} else {
			framework := strings.SplitN(target, "/", 2)[0]
			deps := assets.Project.Frameworks[framework].Dependencies
			if len(deps) == 0 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies", Name: target})
			}
			for name := range deps {
				to := resolve(name)
				if to != "" {
					addAssetsEdge(&doc, "root", to, "direct", target, multi, file, data)
				}
			}
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func addAssetsEdge(doc *model.Document, from, to, kind, target string, conditional bool, file string, data []byte) {
	edge := model.Edge{From: from, To: to, Kind: kind, Evidence: common.Evidence(file, "nuget-assets", "/targets/"+escapePointer(target), data)}
	if conditional {
		edge.Condition = "tfm=" + target
	}
	doc.Edges = append(doc.Edges, edge)
}
