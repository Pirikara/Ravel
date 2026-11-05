package npm

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	semver "github.com/Masterminds/semver/v3"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

type v1Lock struct {
	Name         string               `json:"name"`
	Version      string               `json:"version"`
	Dependencies map[string]v1Package `json:"dependencies"`
}

type v1Package struct {
	Version      string               `json:"version"`
	Resolved     string               `json:"resolved"`
	Integrity    string               `json:"integrity"`
	Dev          bool                 `json:"dev"`
	Optional     bool                 `json:"optional"`
	Bundled      bool                 `json:"bundled"`
	Requires     map[string]string    `json:"requires"`
	Dependencies map[string]v1Package `json:"dependencies"`
}

type v1Manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type v1Item struct {
	name, version, location, pointer, ref string
	data                                  v1Package
}

var exactNpmVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

const (
	maxV1Packages = 100000
	maxV1Depth    = 256
)

func collectV1(file, project string, data []byte) (model.Document, error) {
	var lock v1Lock
	if err := json.Unmarshal(data, &lock); err != nil {
		return model.Document{}, err
	}
	doc := common.NewDocument(file, project, "npm", data)
	if lock.Name != "" {
		doc.Root = &model.ProjectIdentity{Name: lock.Name, Version: lock.Version,
			Evidence: common.Evidence(file, "npm-lock-v1", "/name", data)}
	}
	entries := map[string]v1Item{}
	var walk func(map[string]v1Package, string, string, int)
	walk = func(deps map[string]v1Package, parentLocation, pointer string, depth int) {
		for name, meta := range deps {
			if len(entries) >= maxV1Packages || depth >= maxV1Depth {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "lock_tree_limited"})
				return
			}
			location := path.Join(parentLocation, "node_modules", name)
			packagePointer := pointer + "/" + escapePointer(name)
			version := meta.Version
			if !exactNpmVersion.MatchString(version) {
				version = ""
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "version_unresolved", Name: name})
			}
			ref := "npm:" + common.ID(location+"|"+name+"|"+meta.Version)
			ev := common.Evidence(file, "npm-lock-v1", packagePointer, data)
			component := model.Component{
				ID: ref, Kind: "package", Name: name, Version: version,
				Hashes: common.Integrity(meta.Integrity), Evidence: []model.Evidence{ev},
			}
			if version != "" && common.DefaultNpmRegistry(meta.Resolved) {
				component.PURL = common.NpmPURL(name, version)
			}
			doc.Components = append(doc.Components, component)
			source := meta.Resolved
			if source == "" && version == "" {
				source = meta.Version
			}
			addOrigin(&doc, ref, source, ev)
			entries[location] = v1Item{name: name, version: version, location: location, pointer: packagePointer, ref: ref, data: meta}
			walk(meta.Dependencies, location, packagePointer+"/dependencies", depth+1)
		}
	}
	walk(lock.Dependencies, "", "/dependencies", 0)

	seen := map[string]bool{}
	addEdge := func(from string, to v1Item, kind, condition string, evidence model.Evidence) {
		key := from + "\x00" + to.ref + "\x00" + kind
		if seen[key] {
			return
		}
		seen[key] = true
		doc.Edges = append(doc.Edges, model.Edge{From: from, To: to.ref, Kind: kind, Condition: condition, Evidence: evidence})
		if condition != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: to.name})
		}
	}
	for _, entry := range entries {
		if len(entry.data.Requires) == 0 && len(entry.data.Dependencies) != 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "transitive_graph_unavailable", Name: entry.name})
		}
		for name, required := range entry.data.Requires {
			toRef := resolveV1(entries, entry.location, name)
			to, ok := entries[toRef]
			if !ok {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
				continue
			}
			matches, verified := matchesV1Requirement(required, to)
			if !matches {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
				continue
			}
			if !verified {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dependency_constraint_unverified", Name: name})
			}
			kind, condition := "depends_on", ""
			if entry.data.Optional || to.data.Optional {
				kind, condition = "optional", "optional"
			}
			addEdge(entry.ref, to, kind, condition, common.Evidence(file, "npm-lock-v1", entry.pointer+"/requires/"+escapePointer(name), data))
		}
	}

	manifestPath := filepath.Join(filepath.Dir(file), "package.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	} else {
		doc.Sources = append(doc.Sources, manifestPath)
		var manifest v1Manifest
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
		} else {
			if manifest.Name != "" {
				doc.Root = &model.ProjectIdentity{Name: manifest.Name, Version: manifest.Version,
					Evidence: common.Evidence(manifestPath, "npm-manifest", "/name", manifestData)}
			}
			if lock.Name != "" && manifest.Name != "" && lock.Name != manifest.Name ||
				lock.Version != "" && manifest.Version != "" && lock.Version != manifest.Version {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified"})
			}
			addDirect := func(deps map[string]string, kind, pointer string) {
				for name, required := range deps {
					to, ok := entries[path.Join("node_modules", name)]
					if !ok {
						doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
						continue
					}
					matches, verified := matchesV1Requirement(required, to)
					if !matches {
						doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
						continue
					}
					if !verified {
						doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dependency_constraint_unverified", Name: name})
					}
					edgeKind := kind
					condition := ""
					if kind == "optional" || to.data.Optional {
						edgeKind, condition = "optional", "optional"
					}
					ev := common.Evidence(manifestPath, "npm-manifest", pointer+"/"+escapePointer(name), manifestData)
					ev.Method = "manifest-analysis"
					addEdge("root", to, edgeKind, condition, ev)
				}
			}
			for name := range manifest.OptionalDependencies {
				delete(manifest.Dependencies, name)
			}
			addDirect(manifest.Dependencies, "direct", "/dependencies")
			addDirect(manifest.DevDependencies, "direct_dev", "/devDependencies")
			addDirect(manifest.OptionalDependencies, "optional", "/optionalDependencies")
		}
	}
	adjacent := map[string][]string{}
	for _, edge := range doc.Edges {
		adjacent[edge.From] = append(adjacent[edge.From], edge.To)
	}
	reachable := map[string]bool{"root": true}
	queue := []string{"root"}
	for len(queue) != 0 {
		from := queue[0]
		queue = queue[1:]
		for _, to := range adjacent[from] {
			if !reachable[to] {
				reachable[to] = true
				queue = append(queue, to)
			}
		}
	}
	for _, component := range doc.Components {
		if !reachable[component.ID] {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unreachable_graph", Name: component.Name})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func resolveV1(entries map[string]v1Item, location, name string) string {
	base := location
	for {
		candidate := path.Join(base, "node_modules", name)
		if _, ok := entries[candidate]; ok {
			return candidate
		}
		if base == "" {
			return ""
		}
		idx := strings.LastIndex(base, "node_modules/")
		if idx < 0 {
			base = ""
		} else {
			base = strings.TrimSuffix(base[:idx], "/")
		}
	}
}

func matchesV1Requirement(required string, item v1Item) (matches, verified bool) {
	if required != "" && (required == item.data.Version || required == item.data.Resolved) {
		return true, true
	}
	if item.version == "" {
		return true, false
	}
	constraint, err := semver.NewConstraint(required)
	if err != nil {
		return true, false
	}
	version, err := semver.StrictNewVersion(item.version)
	if err != nil {
		return true, false
	}
	return constraint.Check(version), true
}
