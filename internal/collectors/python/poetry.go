package python

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

type poetryLock struct {
	Package  []poetryPackage `toml:"package"`
	Metadata struct {
		LockVersion string `toml:"lock-version"`
	} `toml:"metadata"`
}

type poetryPackage struct {
	Name         string         `toml:"name"`
	Version      string         `toml:"version"`
	Optional     bool           `toml:"optional"`
	Groups       []string       `toml:"groups"`
	Markers      any            `toml:"markers"`
	Dependencies map[string]any `toml:"dependencies"`
	Files        []struct {
		Hash string `toml:"hash"`
	} `toml:"files"`
	Source struct {
		Type              string `toml:"type"`
		URL               string `toml:"url"`
		Reference         string `toml:"reference"`
		ResolvedReference string `toml:"resolved_reference"`
	} `toml:"source"`
}

type poetryManifest struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Dependencies map[string]any `toml:"dependencies"`
			Group        map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

type poetryNode struct {
	ref       string
	pkg       poetryPackage
	condition string
}

var requirementName = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)

func CollectPoetry(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock poetryLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid poetry.lock: %w", err)
	}
	if lock.Metadata.LockVersion != "1.1" && lock.Metadata.LockVersion != "2.0" && lock.Metadata.LockVersion != "2.1" {
		return model.Document{}, fmt.Errorf("unsupported poetry.lock version %q", lock.Metadata.LockVersion)
	}
	doc := common.NewDocument(file, project, "poetry", data)
	byName := map[string][]poetryNode{}
	for i, pkg := range lock.Package {
		if pkg.Name == "" || pkg.Version == "" {
			return model.Document{}, fmt.Errorf("poetry package %d missing name or version", i)
		}
		ref := "poetry:" + common.ID(fmt.Sprintf("%d|%s|%s", i, pkg.Name, pkg.Version))
		ev := common.Evidence(file, "poetry-lock", fmt.Sprintf("/package/%d", i), data)
		component := model.Component{ID: ref, Kind: "package", Name: pkg.Name, Version: pkg.Version, Evidence: []model.Evidence{ev}}
		if (pkg.Source.Type == "legacy" || pkg.Source.Type == "index") && defaultPyPIIndex(pkg.Source.URL) {
			component.PURL = purl(pkg.Name, pkg.Version)
		} else if pkg.Source.Type == "" && pkg.Source.URL == "" && pkg.Source.Reference == "" && pkg.Source.ResolvedReference == "" {
			// A source-silent lock entry still has a Python package coordinate.
			// This is not evidence that the artifact came from public PyPI.
			component.PURL = purl(pkg.Name, pkg.Version)
			component.PURLBasis = "ecosystem_inferred"
		}
		if len(pkg.Files) == 1 {
			component.Hashes = common.HexSHA256(strings.TrimPrefix(pkg.Files[0].Hash, "sha256:"))
		}
		doc.Components = append(doc.Components, component)
		condition := poetryPackageCondition(pkg)
		if condition != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: pkg.Name})
		}
		byName[normalized(pkg.Name)] = append(byName[normalized(pkg.Name)], poetryNode{ref: ref, pkg: pkg, condition: condition})
		switch pkg.Source.Type {
		case "legacy", "index":
			addURLOrigin(&doc, ref, "declared_registry", pkg.Source.URL, "", ev, pkg.Name)
		case "git":
			revision := pkg.Source.ResolvedReference
			if !commitID.MatchString(revision) {
				revision = ""
			}
			addURLOrigin(&doc, ref, "vcs", pkg.Source.URL, revision, ev, pkg.Name)
		case "url":
			addURLOrigin(&doc, ref, "download_url", pkg.Source.URL, "", ev, pkg.Name)
		case "directory", "file":
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
		default:
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: pkg.Name})
		}
	}
	resolve := func(name string) poetryNode {
		matches := byName[normalized(name)]
		if len(matches) == 1 {
			return matches[0]
		}
		code := "unresolved_dependency"
		if len(matches) > 1 {
			code = "ambiguous_dependency"
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name})
		return poetryNode{}
	}
	for _, nodes := range byName {
		for _, n := range nodes {
			for name, spec := range n.pkg.Dependencies {
				to := resolve(name)
				if to.ref == "" {
					continue
				}
				condition := strings.Join(nonempty(n.condition, poetryDependencyCondition(spec), to.condition), " && ")
				if condition != "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: name})
				}
				doc.Edges = append(doc.Edges, model.Edge{From: n.ref, To: to.ref, Kind: "depends_on", Condition: condition, Evidence: common.Evidence(file, "poetry-lock", "/package/dependencies/"+name, data)})
			}
		}
	}
	manifestData, err := os.ReadFile(filepath.Join(filepath.Dir(file), "pyproject.toml"))
	if err != nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	} else {
		doc.Sources = append(doc.Sources, filepath.Join(filepath.Dir(file), "pyproject.toml"))
		var manifest poetryManifest
		if err := toml.Unmarshal(manifestData, &manifest); err != nil {
			return model.Document{}, fmt.Errorf("invalid pyproject.toml: %w", err)
		}
		type rootDependency struct{ name, condition string }
		roots := []rootDependency{}
		seenRoots := map[string]bool{}
		addRoot := func(name, condition string) {
			key := normalized(name) + "|" + condition
			if seenRoots[key] {
				return
			}
			seenRoots[key] = true
			roots = append(roots, rootDependency{name: name, condition: condition})
		}
		for _, req := range manifest.Project.Dependencies {
			match := requirementName.FindStringSubmatch(req)
			if len(match) == 2 {
				addRoot(match[1], "")
			}
		}
		for extra, requirements := range manifest.Project.OptionalDependencies {
			for _, req := range requirements {
				match := requirementName.FindStringSubmatch(req)
				if len(match) == 2 {
					addRoot(match[1], "extra="+extra)
				}
			}
		}
		for name, spec := range manifest.Tool.Poetry.Dependencies {
			if strings.EqualFold(name, "python") {
				continue
			}
			addRoot(name, poetryDependencyCondition(spec))
		}
		for group, entry := range manifest.Tool.Poetry.Group {
			for name, spec := range entry.Dependencies {
				addRoot(name, strings.Join(nonempty("group="+group, poetryDependencyCondition(spec)), " && "))
			}
		}
		if len(roots) == 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
		}
		for _, root := range roots {
			to := resolve(root.name)
			if to.ref == "" {
				continue
			}
			condition := strings.Join(nonempty(root.condition, to.condition), " && ")
			if condition != "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: root.name})
			}
			doc.Edges = append(doc.Edges, model.Edge{From: "root", To: to.ref, Kind: "direct", Condition: condition, Evidence: common.Evidence(filepath.Join(filepath.Dir(file), "pyproject.toml"), "poetry-manifest", "/dependencies/"+root.name, manifestData)})
		}
		// Poetry's content-hash is not checked here; a changed manifest can give
		// incorrect root edges even when package-to-package edges are intact.
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified"})
	}
	common.Finalize(&doc)
	return doc, nil
}

func poetryPackageCondition(pkg poetryPackage) string {
	conditions := []string{}
	if pkg.Optional {
		conditions = append(conditions, "optional")
	}
	if len(pkg.Groups) > 0 {
		main := false
		for _, group := range pkg.Groups {
			if group == "main" {
				main = true
			}
		}
		if !main {
			conditions = append(conditions, "group="+strings.Join(pkg.Groups, "|"))
		}
	}
	switch marker := pkg.Markers.(type) {
	case string:
		if marker != "" {
			conditions = append(conditions, marker)
		}
	case map[string]any:
		keys := make([]string, 0, len(marker))
		for key := range marker {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		clauses := []string{}
		for _, key := range keys {
			if text, ok := marker[key].(string); ok && text != "" {
				clauses = append(clauses, "(group="+key+" && ("+text+"))")
			}
		}
		if len(clauses) > 0 {
			conditions = append(conditions, "("+strings.Join(clauses, " || ")+")")
		}
	}
	return strings.Join(conditions, " && ")
}

func poetryDependencyCondition(spec any) string {
	switch value := spec.(type) {
	case map[string]any:
		conditions := []string{}
		if optional, ok := value["optional"].(bool); ok && optional {
			conditions = append(conditions, "optional")
		}
		if marker, ok := value["markers"].(string); ok && marker != "" {
			conditions = append(conditions, marker)
		}
		return strings.Join(conditions, " && ")
	case []any:
		return "variant"
	}
	return ""
}
