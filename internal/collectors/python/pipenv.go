package python

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

type pipenvMetadata struct {
	Spec    int `json:"pipfile-spec"`
	Sources []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"sources"`
}

type pipenvPackage struct {
	Version string   `json:"version"`
	Markers string   `json:"markers"`
	Index   string   `json:"index"`
	Git     string   `json:"git"`
	Ref     string   `json:"ref"`
	File    string   `json:"file"`
	Path    string   `json:"path"`
	Hashes  []string `json:"hashes"`
}

type pipenvEntry struct {
	name     string
	category string
	ref      string
	markers  string
}

var pipenvRevision = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

func CollectPipenv(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(data, &sections); err != nil {
		return model.Document{}, fmt.Errorf("invalid Pipfile.lock: %w", err)
	}
	var metadata pipenvMetadata
	if err := json.Unmarshal(sections["_meta"], &metadata); err != nil {
		return model.Document{}, fmt.Errorf("invalid Pipfile.lock metadata: %w", err)
	}
	if metadata.Spec != 6 {
		return model.Document{}, fmt.Errorf("unsupported Pipfile.lock spec %d", metadata.Spec)
	}
	if len(sections) < 2 {
		return model.Document{}, fmt.Errorf("Pipfile.lock has no package sections")
	}
	doc := common.NewDocument(file, project, "pipenv", data)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "transitive_graph_unavailable"})
	sources := map[string][]string{}
	allSources := []string{}
	for _, source := range metadata.Sources {
		if source.Name == "" || source.URL == "" {
			continue
		}
		sources[source.Name] = append(sources[source.Name], source.URL)
		allSources = append(allSources, source.URL)
	}
	var categories []string
	for category := range sections {
		if category != "_meta" {
			categories = append(categories, category)
		}
	}
	sort.Strings(categories)
	entries := map[string]map[string][]pipenvEntry{}
	for _, category := range categories {
		var packages map[string]pipenvPackage
		if err := json.Unmarshal(sections[category], &packages); err != nil {
			return model.Document{}, fmt.Errorf("invalid Pipfile.lock section %s: %w", category, err)
		}
		if entries[category] == nil {
			entries[category] = map[string][]pipenvEntry{}
		}
		var names []string
		for name := range packages {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			pkg := packages[name]
			if name == "" {
				return model.Document{}, fmt.Errorf("empty Pipenv package name")
			}
			version := ""
			if pkg.Version != "" {
				if !strings.HasPrefix(pkg.Version, "==") || len(pkg.Version) <= 2 {
					return model.Document{}, fmt.Errorf("Pipenv package %s has non-exact version %q", name, pkg.Version)
				}
				version = strings.TrimPrefix(pkg.Version, "==")
			}
			if version == "" && pkg.Git == "" && pkg.File == "" && pkg.Path == "" {
				return model.Document{}, fmt.Errorf("Pipenv package %s has no pinned version or explicit source", name)
			}
			ref := "pipenv:" + common.ID(category+"|"+name+"|"+version)
			entry := pipenvEntry{name: name, category: category, ref: ref, markers: pkg.Markers}
			entries[category][normalized(name)] = append(entries[category][normalized(name)], entry)
			ev := common.Evidence(file, "pipenv-lock", "/"+category+"/"+common.ID(name), data)
			component := model.Component{ID: ref, Kind: "package", Name: name, Version: version, Evidence: []model.Evidence{ev}}
			if pkg.Git == "" && pkg.File == "" && pkg.Path == "" {
				candidateSources := allSources
				if pkg.Index != "" {
					candidateSources = sources[pkg.Index]
				}
				if len(candidateSources) == 1 && defaultPyPIIndex(candidateSources[0]) {
					component.PURL = purl(name, version)
				}
			}
			doc.Components = append(doc.Components, component)
			if pkg.Markers != "" || category != "default" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: name})
			}
			addPipenvOrigins(&doc, ref, name, pkg, sources, allSources, ev)
		}
	}
	manifestPath := filepath.Join(filepath.Dir(file), "Pipfile")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	} else {
		doc.Sources = append(doc.Sources, manifestPath)
		var manifest map[string]any
		if err := toml.Unmarshal(manifestData, &manifest); err != nil {
			return model.Document{}, fmt.Errorf("invalid Pipfile: %w", err)
		}
		for _, category := range categories {
			manifestCategory := category
			if category == "default" {
				manifestCategory = "packages"
			} else if category == "develop" {
				manifestCategory = "dev-packages"
			}
			requires, ok := manifest[manifestCategory].(map[string]any)
			if !ok {
				continue
			}
			var names []string
			for name := range requires {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				matches := entries[category][normalized(name)]
				if len(matches) != 1 {
					code := "unresolved_dependency"
					if len(matches) > 1 {
						code = "ambiguous_dependency"
					}
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name})
					continue
				}
				condition := ""
				if category != "default" {
					condition = "group=" + category
				}
				if matches[0].markers != "" {
					if condition != "" {
						condition += " && "
					}
					condition += "marker=(" + matches[0].markers + ")"
				}
				doc.Edges = append(doc.Edges, model.Edge{From: "root", To: matches[0].ref, Kind: "direct", Condition: condition, Evidence: common.Evidence(manifestPath, "pipenv-manifest", "/"+manifestCategory+"/"+common.ID(name), manifestData)})
			}
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified"})
	}
	common.Finalize(&doc)
	return doc, nil
}

func addPipenvOrigins(doc *model.Document, ref, name string, pkg pipenvPackage, sources map[string][]string, allSources []string, ev model.Evidence) {
	appendURL := func(kind, raw, revision string) bool {
		if raw == "" {
			return false
		}
		if strings.HasPrefix(raw, "git+") {
			raw = strings.TrimPrefix(raw, "git+")
		}
		clean := safeurl.Clean(raw)
		if clean == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: name})
			return false
		}
		if !pipenvRevision.MatchString(revision) {
			revision = ""
		}
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: kind, SafeURL: clean, Revision: revision, Status: "declared", Evidence: ev})
		return true
	}
	if pkg.Git != "" {
		if !appendURL("vcs", pkg.Git, pkg.Ref) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
		}
		return
	}
	if pkg.Path != "" {
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
		return
	}
	if pkg.File != "" {
		if strings.HasPrefix(pkg.File, "http://") || strings.HasPrefix(pkg.File, "https://") {
			if !appendURL("download_url", pkg.File, "") {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
			}
		} else {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
		}
		return
	}
	urls := allSources
	if pkg.Index != "" {
		urls = sources[pkg.Index]
	}
	if len(urls) > 1 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_source", Name: name})
	}
	count := 0
	for _, raw := range urls {
		if appendURL("declared_registry", raw, "") {
			count++
		}
	}
	if count == 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
	}
}
