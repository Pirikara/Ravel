package yarn

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

type berryEntry struct {
	Version          string         `yaml:"version"`
	Resolution       string         `yaml:"resolution"`
	Dependencies     map[string]any `yaml:"dependencies"`
	DependenciesMeta map[string]struct {
		Optional bool `yaml:"optional"`
	} `yaml:"dependenciesMeta"`
	PeerDependencies map[string]string `yaml:"peerDependencies"`
	LinkType         string            `yaml:"linkType"`
}

type berryNode struct {
	ref, name, resolution, key string
	entry                      berryEntry
	root                       bool
}

func collectBerry(file, project string, data []byte) (model.Document, error) {
	var entries map[string]yaml.Node
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return model.Document{}, fmt.Errorf("invalid Yarn Berry lockfile: %w", err)
	}
	if _, ok := entries["__metadata"]; !ok {
		return model.Document{}, fmt.Errorf("Yarn Berry lockfile has no __metadata")
	}
	doc := common.NewDocument(file, project, "yarn", data)
	descriptors := map[string]berryNode{}
	nodes := []berryNode{}
	for key, raw := range entries {
		if key == "__metadata" {
			continue
		}
		var entry berryEntry
		if err := raw.Decode(&entry); err != nil {
			return model.Document{}, fmt.Errorf("invalid Yarn entry: %w", err)
		}
		name := berryName(entry.Resolution)
		if !classicName.MatchString(name) || entry.Version == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "invalid Yarn resolution"})
			continue
		}
		root := strings.HasSuffix(entry.Resolution, "@workspace:.")
		ref := "yarn:" + common.ID(key+"|"+entry.Resolution)
		if root {
			ref = "root"
		}
		node := berryNode{ref: ref, name: name, resolution: entry.Resolution, key: key, entry: entry, root: root}
		nodes = append(nodes, node)
		for _, descriptor := range strings.Split(key, ", ") {
			if prior, exists := descriptors[descriptor]; exists && prior.ref != ref {
				descriptors[descriptor] = berryNode{}
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "duplicate_spec", Name: "Yarn descriptor"})
			} else if !exists {
				descriptors[descriptor] = node
			}
		}
	}
	queue := []berryNode{}
	for _, node := range nodes {
		if node.root {
			queue = append(queue, node)
		}
	}
	if len(queue) == 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
		queue = append(queue, nodes...)
	} else if len(queue) > 1 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: "Yarn project root"})
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if seen[node.ref] {
			continue
		}
		seen[node.ref] = true
		if !node.root {
			emitBerryComponent(&doc, file, data, node)
		}
		for depName, rawRange := range node.entry.Dependencies {
			rangeText, ok := rawRange.(string)
			if !ok {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: depName})
				continue
			}
			target := descriptors[berryDescriptor(depName, rangeText)]
			if target.ref == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: depName})
				continue
			}
			condition := ""
			if node.entry.DependenciesMeta[depName].Optional {
				condition = "optional"
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: depName})
			}
			kind := "depends_on"
			if node.root {
				kind = "direct"
			}
			ev := common.Evidence(file, "yarn-berry", "/entries/"+common.ID(node.key)+"/dependencies/"+common.ID(depName), data)
			doc.Edges = append(doc.Edges, model.Edge{From: node.ref, To: target.ref, Kind: kind, Condition: condition, Evidence: ev})
			queue = append(queue, target)
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func emitBerryComponent(doc *model.Document, file string, data []byte, node berryNode) {
	ev := common.Evidence(file, "yarn-berry", "/entries/"+common.ID(node.key), data)
	local := strings.Contains(node.resolution, "@workspace:") || node.entry.LinkType == "soft"
	component := model.Component{ID: node.ref, Kind: "package", Name: node.name, Version: node.entry.Version, Evidence: []model.Evidence{ev}}
	if local {
		component.Kind = "application"
		if node.entry.Version == "0.0.0-use.local" {
			loadBerryWorkspaceVersion(doc, file, node, &component)
		}
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: node.ref, Kind: "local", Status: "declared", Evidence: ev})
	} else {
		source := berrySource(node.resolution)
		if strings.Contains(node.resolution, "@npm:") && common.DefaultNpmRegistry(source) {
			component.PURL = common.NpmPURL(node.name, node.entry.Version)
		}
		if source == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: node.name})
		} else {
			clean := safeurl.Clean(source)
			if clean == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: node.name})
			} else {
				kind := "download_url"
				if strings.Contains(node.resolution, "@git+") {
					kind = "vcs"
				}
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: node.ref, Kind: kind, SafeURL: clean, Status: "declared", Evidence: ev})
			}
		}
	}
	doc.Components = append(doc.Components, component)
	if len(node.entry.PeerDependencies) > 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: "peer dependencies of " + node.name})
	}
}

func loadBerryWorkspaceVersion(doc *model.Document, lockfile string, node berryNode, component *model.Component) {
	component.Version = ""
	prefix := node.name + "@workspace:"
	if !strings.HasPrefix(node.resolution, prefix) {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "workspace_version_unresolved", Name: node.name})
		return
	}
	relative := strings.TrimPrefix(node.resolution, prefix)
	if relative == "" || filepath.IsAbs(relative) {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "workspace_version_unresolved", Name: node.name})
		return
	}
	base := filepath.Dir(lockfile)
	manifestPath := filepath.Join(base, relative, "package.json")
	realBase, baseErr := filepath.EvalSymlinks(base)
	realManifest, manifestErr := filepath.EvalSymlinks(manifestPath)
	if baseErr != nil || manifestErr != nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "workspace_version_unresolved", Name: node.name})
		return
	}
	within, err := filepath.Rel(realBase, realManifest)
	if err != nil || within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "workspace_version_unresolved", Name: node.name})
		return
	}
	info, err := os.Stat(realManifest)
	if err != nil || info.IsDir() || info.Size() > 1<<20 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "workspace_version_unresolved", Name: node.name})
		return
	}
	data, err := os.ReadFile(realManifest)
	if err != nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "workspace_version_unresolved", Name: node.name})
		return
	}
	doc.Sources = append(doc.Sources, realManifest)
	var manifest struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.Name != node.name || manifest.Version == "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "workspace_manifest_mismatch", Name: node.name})
		return
	}
	component.Version = manifest.Version
	component.Evidence = append(component.Evidence, common.Evidence(realManifest, "yarn-workspace-manifest", "/version", data))
}

func berryName(resolution string) string {
	if strings.HasPrefix(resolution, "@") {
		at := strings.Index(resolution[1:], "@")
		if at < 0 {
			return ""
		}
		return resolution[:at+1]
	}
	at := strings.IndexByte(resolution, '@')
	if at <= 0 {
		return ""
	}
	return resolution[:at]
}

func berrySource(resolution string) string {
	name := berryName(resolution)
	if name == "" {
		return ""
	}
	value := strings.TrimPrefix(resolution, name+"@")
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return value
	}
	if strings.HasPrefix(value, "git+") {
		candidate := strings.TrimPrefix(value, "git+")
		if parsed, err := url.Parse(candidate); err == nil && parsed.Host != "" {
			return candidate
		}
	}
	return ""
}

func berryDescriptor(name, rangeText string) string {
	if strings.Contains(rangeText, ":") {
		return name + "@" + rangeText
	}
	return name + "@npm:" + rangeText
}
