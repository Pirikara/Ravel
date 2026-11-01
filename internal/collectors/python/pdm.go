package python

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

type pdmLock struct {
	Metadata struct {
		LockVersion string           `toml:"lock_version"`
		Groups      []string         `toml:"groups"`
		Targets     []map[string]any `toml:"targets"`
	} `toml:"metadata"`
	Packages []pdmPackage `toml:"package"`
}

type pdmPackage struct {
	Name           string   `toml:"name"`
	Version        string   `toml:"version"`
	Dependencies   []string `toml:"dependencies"`
	Groups         []string `toml:"groups"`
	Extras         []string `toml:"extras"`
	Marker         string   `toml:"marker"`
	RequiresPython string   `toml:"requires_python"`
	URL            string   `toml:"url"`
	Git            string   `toml:"git"`
	Path           string   `toml:"path"`
	Revision       string   `toml:"revision"`
	Files          []struct {
		File string `toml:"file"`
		URL  string `toml:"url"`
		Hash string `toml:"hash"`
	} `toml:"files"`
}

type pdmManifest struct {
	Project struct {
		Dependencies []string            `toml:"dependencies"`
		Optional     map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	Tool             struct {
		PDM struct {
			Dev map[string][]string `toml:"dev-dependencies"`
		} `toml:"pdm"`
	} `toml:"tool"`
}

type pdmNode struct {
	pkg   pdmPackage
	ref   string
	index int
}

var pdmRequirement = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[([^\]]+)\])?`)

func CollectPDM(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock pdmLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid pdm.lock: %w", err)
	}
	if !strings.HasPrefix(lock.Metadata.LockVersion, "4.") || len(lock.Packages) == 0 {
		return model.Document{}, fmt.Errorf("unsupported pdm.lock version or empty package list")
	}
	doc := common.NewDocument(file, project, "pdm", data)
	if len(lock.Metadata.Targets) > 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: "lock targets"})
	}
	byName := map[string][]pdmNode{}
	byRef := map[string]pdmPackage{}
	nodes := make([]pdmNode, 0, len(lock.Packages))
	for i, pkg := range lock.Packages {
		if pkg.Name == "" || pkg.Version == "" {
			return model.Document{}, fmt.Errorf("PDM package %d missing identity", i)
		}
		ref := "pdm:" + common.ID(fmt.Sprintf("%d|%s|%s|%s", i, normalized(pkg.Name), pkg.Version, strings.Join(pkg.Extras, ",")))
		n := pdmNode{pkg: pkg, ref: ref, index: i}
		nodes = append(nodes, n)
		byName[normalized(pkg.Name)] = append(byName[normalized(pkg.Name)], n)
		byRef[ref] = pkg
		ev := common.Evidence(file, "pdm-lock", fmt.Sprintf("/package/%d", i), data)
		component := model.Component{ID: ref, Kind: "package", Name: pkg.Name, Version: pkg.Version, Evidence: []model.Evidence{ev}}
		doc.Components = append(doc.Components, component)
		if pkg.Marker != "" || pkg.RequiresPython != "" || len(pkg.Extras) > 0 || hasNonDefaultGroup(pkg.Groups) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: pkg.Name})
		}
		addPDMOrigins(&doc, n, ev)
	}
	resolve := func(spec string) string {
		name, extras, _ := parsePDMRequirement(spec)
		if name == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: spec})
			return ""
		}
		var matches []pdmNode
		for _, candidate := range byName[normalized(name)] {
			if sameExtras(candidate.pkg.Extras, extras) {
				matches = append(matches, candidate)
			}
		}
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
	for _, node := range nodes {
		for j, spec := range node.pkg.Dependencies {
			to := resolve(spec)
			if to == "" {
				continue
			}
			_, _, marker := parsePDMRequirement(spec)
			condition := pdmCondition(node.pkg, marker, len(lock.Metadata.Targets) > 0)
			if target := byRef[to]; target.Marker != "" {
				condition = appendPDMCondition(condition, "marker=("+target.Marker+")")
			}
			if target := byRef[to]; target.RequiresPython != "" {
				condition = appendPDMCondition(condition, "python=("+target.RequiresPython+")")
			}
			doc.Edges = append(doc.Edges, model.Edge{From: node.ref, To: to, Kind: "depends_on", Condition: condition, Evidence: common.Evidence(file, "pdm-lock", fmt.Sprintf("/package/%d/dependencies/%d", node.index, j), data)})
		}
	}
	manifestPath := filepath.Join(filepath.Dir(file), "pyproject.toml")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	} else {
		doc.Sources = append(doc.Sources, manifestPath)
		var manifest pdmManifest
		if err := toml.Unmarshal(manifestData, &manifest); err != nil {
			return model.Document{}, fmt.Errorf("invalid pyproject.toml: %w", err)
		}
		groups := map[string][]string{"default": manifest.Project.Dependencies}
		for name, specs := range manifest.Project.Optional {
			groups[name] = append(groups[name], specs...)
		}
		for name, specs := range manifest.Tool.PDM.Dev {
			groups[name] = append(groups[name], specs...)
		}
		for name, values := range manifest.DependencyGroups {
			for _, value := range values {
				if spec, ok := value.(string); ok {
					groups[name] = append(groups[name], spec)
				} else {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
				}
			}
		}
		var groupNames []string
		for name := range groups {
			groupNames = append(groupNames, name)
		}
		sort.Strings(groupNames)
		for _, group := range groupNames {
			for i, spec := range groups[group] {
				to := resolve(spec)
				if to == "" {
					continue
				}
				_, _, marker := parsePDMRequirement(spec)
				parts := []string{}
				if group != "default" {
					parts = append(parts, "group="+group)
				}
				if marker != "" {
					parts = append(parts, "marker=("+marker+")")
				}
				if len(lock.Metadata.Targets) > 0 {
					parts = append(parts, "target=unselected")
				}
				if target := byRef[to]; target.Marker != "" {
					parts = append(parts, "marker=("+target.Marker+")")
				}
				if target := byRef[to]; target.RequiresPython != "" {
					parts = append(parts, "python=("+target.RequiresPython+")")
				}
				doc.Edges = append(doc.Edges, model.Edge{From: "root", To: to, Kind: "direct", Condition: strings.Join(parts, " && "), Evidence: common.Evidence(manifestPath, "pdm-manifest", fmt.Sprintf("/groups/%s/%d", group, i), manifestData)})
			}
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified"})
	}
	common.Finalize(&doc)
	return doc, nil
}

func parsePDMRequirement(spec string) (string, []string, string) {
	parts := strings.SplitN(spec, ";", 2)
	match := pdmRequirement.FindStringSubmatch(strings.TrimSpace(parts[0]))
	if match == nil {
		return "", nil, ""
	}
	var extras []string
	if match[2] != "" {
		for _, extra := range strings.Split(match[2], ",") {
			extras = append(extras, strings.TrimSpace(extra))
		}
	}
	marker := ""
	if len(parts) == 2 {
		marker = strings.TrimSpace(parts[1])
	}
	return match[1], extras, marker
}

func sameExtras(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left, right := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func hasNonDefaultGroup(groups []string) bool {
	for _, group := range groups {
		if group != "default" {
			return true
		}
	}
	return false
}

func pdmCondition(pkg pdmPackage, marker string, target bool) string {
	var parts []string
	if hasNonDefaultGroup(pkg.Groups) {
		parts = append(parts, "group=unselected")
	}
	if len(pkg.Extras) > 0 {
		parts = append(parts, "extra="+strings.Join(pkg.Extras, ","))
	}
	if pkg.Marker != "" {
		parts = append(parts, "marker=("+pkg.Marker+")")
	}
	if pkg.RequiresPython != "" {
		parts = append(parts, "python=("+pkg.RequiresPython+")")
	}
	if marker != "" {
		parts = append(parts, "marker=("+marker+")")
	}
	if target {
		parts = append(parts, "target=unselected")
	}
	return strings.Join(parts, " && ")
}

func appendPDMCondition(condition, item string) string {
	if condition == "" {
		return item
	}
	return condition + " && " + item
}

func addPDMOrigins(doc *model.Document, node pdmNode, ev model.Evidence) {
	pkg := node.pkg
	count := 0
	appendURL := func(kind, raw string) {
		if raw == "" {
			return
		}
		if strings.HasPrefix(raw, "git+") {
			raw = strings.TrimPrefix(raw, "git+")
		}
		clean := safeurl.Clean(raw)
		if clean == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: pkg.Name})
			return
		}
		rev := ""
		if commitID.MatchString(pkg.Revision) {
			rev = pkg.Revision
		}
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: node.ref, Kind: kind, SafeURL: clean, Revision: rev, Status: "declared", Evidence: ev})
		count++
	}
	appendURL("vcs", pkg.Git)
	appendURL("download_url", pkg.URL)
	if pkg.Path != "" {
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: node.ref, Kind: "local", Status: "declared", Evidence: ev})
		count++
	}
	for i, artifact := range pkg.Files {
		if artifact.URL == "" {
			continue
		}
		artifactEvidence := ev
		artifactEvidence.Pointer = fmt.Sprintf("/package/%d/files/%d", node.index, i)
		clean := safeurl.Clean(artifact.URL)
		if clean == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: pkg.Name})
			continue
		}
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: node.ref, Kind: "download_url", SafeURL: clean, Status: "declared", Evidence: artifactEvidence})
		count++
	}
	if count == 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: pkg.Name})
	}
}
