package cocoapods

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

type lockfile struct {
	Pods            []yaml.Node                  `yaml:"PODS"`
	Dependencies    []string                     `yaml:"DEPENDENCIES"`
	SpecRepos       map[string][]string          `yaml:"SPEC REPOS"`
	ExternalSources map[string]map[string]string `yaml:"EXTERNAL SOURCES"`
	CheckoutOptions map[string]map[string]string `yaml:"CHECKOUT OPTIONS"`
	SpecChecksums   map[string]string            `yaml:"SPEC CHECKSUMS"`
	PodfileChecksum string                       `yaml:"PODFILE CHECKSUM"`
	CocoaPods       string                       `yaml:"COCOAPODS"`
}

type pod struct {
	name    string
	version string
	deps    []string
	ref     string
	index   int
}

var versionEntry = regexp.MustCompile(`^(.+?) \(([^()]*)\)$`)
var revision = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid Podfile.lock: %w", err)
	}
	if lock.Pods == nil {
		return model.Document{}, fmt.Errorf("Podfile.lock has no PODS list")
	}
	doc := common.NewDocument(file, project, "cocoapods", data)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "target_conditions_unresolved"})
	if len(lock.Dependencies) == 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	}
	byName := map[string][]pod{}
	pods := make([]pod, 0, len(lock.Pods))
	repos := map[string][]string{}
	for repo, names := range lock.SpecRepos {
		for _, name := range names {
			repos[name] = append(repos[name], repo)
		}
	}
	for i, item := range lock.Pods {
		entry, deps, err := parseItem(item)
		if err != nil {
			return model.Document{}, fmt.Errorf("invalid PODS entry %d: %w", i, err)
		}
		name, version, ok := parseNameVersion(entry)
		if !ok || name == "" || version == "" {
			return model.Document{}, fmt.Errorf("PODS entry %d has no name or version", i)
		}
		ref := "cocoapods:" + common.ID(fmt.Sprintf("%d|%s|%s", i, name, version))
		p := pod{name: name, version: version, deps: deps, ref: ref, index: i}
		pods = append(pods, p)
		byName[name] = append(byName[name], p)
		ev := common.Evidence(file, "cocoapods-lock", fmt.Sprintf("/PODS/%d", i), data)
		root := rootName(name)
		purl := ""
		if len(lock.ExternalSources[root]) == 0 && len(lock.CheckoutOptions[root]) == 0 && len(repos[root]) == 1 {
			repo := repos[root][0]
			if repo == "trunk" {
				repo = "https://cdn.cocoapods.org/"
			}
			if clean := safeurl.Clean(repo); clean != "" {
				purl = podPURL(name, version, clean)
			}
		}
		doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: name, Version: version, PURL: purl, Evidence: []model.Evidence{ev}})
		originCount := addExternal(&doc, ref, root, lock.ExternalSources[root], lock.CheckoutOptions[root], ev)
		if originCount == 0 && len(lock.ExternalSources[root]) == 0 && len(lock.CheckoutOptions[root]) == 0 {
			if len(repos[root]) > 1 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_source", Name: name})
			}
			for _, repo := range repos[root] {
				clean := repo
				if repo == "trunk" {
					clean = "https://cdn.cocoapods.org/"
				}
				clean = safeurl.Clean(clean)
				if clean == "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: name})
					continue
				}
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "declared_registry", SafeURL: clean, Status: "declared", Evidence: common.Evidence(file, "cocoapods-lock", "/SPEC REPOS/"+common.ID(repo), data)})
				originCount++
			}
		}
		if originCount == 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
		}
	}
	resolve := func(name string) string {
		matches := byName[name]
		if len(matches) == 1 {
			return matches[0].ref
		}
		code := "unresolved_dependency"
		if len(matches) > 1 {
			code = "ambiguous_dependency"
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name})
		return ""
	}
	for _, p := range pods {
		if len(byName[p.name]) > 1 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "duplicate_spec", Name: p.name})
		}
		for j, spec := range p.deps {
			name := dependencyName(spec)
			if name == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency"})
				continue
			}
			to := resolve(name)
			if to == "" {
				continue
			}
			doc.Edges = append(doc.Edges, model.Edge{From: p.ref, To: to, Kind: "depends_on", Condition: "target=unselected", Evidence: common.Evidence(file, "cocoapods-lock", fmt.Sprintf("/PODS/%d/%d", p.index, j), data)})
		}
	}
	for i, spec := range lock.Dependencies {
		name := dependencyName(spec)
		if name == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency"})
			continue
		}
		to := resolve(name)
		if to == "" {
			continue
		}
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: to, Kind: "direct", Condition: "target=unselected", Evidence: common.Evidence(file, "cocoapods-lock", fmt.Sprintf("/DEPENDENCIES/%d", i), data)})
	}
	common.Finalize(&doc)
	return doc, nil
}

func parseItem(item yaml.Node) (string, []string, error) {
	switch item.Kind {
	case yaml.ScalarNode:
		return item.Value, nil, nil
	case yaml.MappingNode:
		if len(item.Content) != 2 || item.Content[0].Kind != yaml.ScalarNode || item.Content[1].Kind != yaml.SequenceNode {
			return "", nil, fmt.Errorf("expected one pod with a dependency list")
		}
		var deps []string
		for _, child := range item.Content[1].Content {
			if child.Kind != yaml.ScalarNode {
				return "", nil, fmt.Errorf("non-string dependency")
			}
			deps = append(deps, child.Value)
		}
		return item.Content[0].Value, deps, nil
	default:
		return "", nil, fmt.Errorf("expected pod string or mapping")
	}
}

func parseNameVersion(value string) (string, string, bool) {
	match := versionEntry.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return "", "", false
	}
	return strings.TrimSpace(match[1]), strings.TrimSpace(match[2]), true
}

func dependencyName(value string) string {
	value = strings.TrimSpace(value)
	if i := strings.Index(value, " ("); i >= 0 {
		value = value[:i]
	}
	return strings.TrimSpace(value)
}

func rootName(name string) string {
	if i := strings.IndexByte(name, '/'); i >= 0 {
		return name[:i]
	}
	return name
}

func podPURL(name, version, repo string) string {
	parts := strings.Split(name, "/")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	var qualifiers packageurl.Qualifiers
	if repo != "https://cdn.cocoapods.org/" {
		qualifiers = packageurl.QualifiersFromMap(map[string]string{"repository_url": repo})
	}
	for _, part := range parts[1:] {
		if part == "" {
			return ""
		}
	}
	return packageurl.NewPackageURL("cocoapods", "", parts[0], version, qualifiers, strings.Join(parts[1:], "/")).ToString()
}

func addExternal(doc *model.Document, ref, name string, external, checkout map[string]string, ev model.Evidence) int {
	if len(external) == 0 && len(checkout) == 0 {
		return 0
	}
	count := 0
	appendURL := func(kind, raw, rev string) {
		if raw == "" {
			return
		}
		clean := safeurl.Clean(raw)
		if clean == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: name})
			return
		}
		if !revision.MatchString(rev) {
			rev = ""
		}
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: kind, SafeURL: clean, Revision: rev, Status: "declared", Evidence: ev})
		count++
	}
	gitURL := checkout[":git"]
	if gitURL == "" {
		gitURL = external[":git"]
	}
	appendURL("vcs", gitURL, checkout[":commit"])
	appendURL("download_url", external[":http"], "")
	if podspec := external[":podspec"]; podspec != "" {
		if strings.HasPrefix(podspec, "https://") || strings.HasPrefix(podspec, "http://") {
			appendURL("podspec", podspec, "")
		} else {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
			count++
		}
	}
	if external[":path"] != "" {
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
		count++
	}
	return count
}
