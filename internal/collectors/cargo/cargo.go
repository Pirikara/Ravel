package cargo

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

type lockfile struct {
	Version int             `toml:"version"`
	Package []lockedPackage `toml:"package"`
}

type lockedPackage struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source"`
	Checksum     string   `toml:"checksum"`
	Dependencies []string `toml:"dependencies"`
}

type manifest struct {
	Package struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	} `toml:"package"`
	Dependencies      map[string]any `toml:"dependencies"`
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
	Target            map[string]struct {
		Dependencies      map[string]any `toml:"dependencies"`
		DevDependencies   map[string]any `toml:"dev-dependencies"`
		BuildDependencies map[string]any `toml:"build-dependencies"`
	} `toml:"target"`
}

type node struct {
	ref  string
	pkg  lockedPackage
	root bool
}

func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid Cargo.lock: %w", err)
	}
	if (lock.Version != 3 && lock.Version != 4) || len(lock.Package) == 0 {
		return model.Document{}, fmt.Errorf("unsupported Cargo.lock version or empty package list")
	}
	doc := common.NewDocument(file, project, "cargo", data)
	var rootName, rootVersion string
	manifestData, manifestErr := os.ReadFile(filepath.Join(filepath.Dir(file), "Cargo.toml"))
	var m manifest
	if manifestErr == nil {
		doc.Sources = append(doc.Sources, filepath.Join(filepath.Dir(file), "Cargo.toml"))
		if err := toml.Unmarshal(manifestData, &m); err != nil {
			return model.Document{}, fmt.Errorf("invalid Cargo.toml: %w", err)
		}
		rootName, rootVersion = m.Package.Name, m.Package.Version
	}
	if rootName == "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	}
	nodes := []node{}
	byName := map[string][]node{}
	rootCount := 0
	for i, pkg := range lock.Package {
		if pkg.Name == "" || pkg.Version == "" {
			return model.Document{}, fmt.Errorf("Cargo package %d missing name or version", i)
		}
		root := pkg.Source == "" && pkg.Name == rootName && pkg.Version == rootVersion
		ref := "cargo:" + common.ID(fmt.Sprintf("%d|%s|%s|%s", i, pkg.Name, pkg.Version, pkg.Source))
		if root {
			ref = "root"
			rootCount++
		}
		n := node{ref: ref, pkg: pkg, root: root}
		nodes = append(nodes, n)
		byName[pkg.Name] = append(byName[pkg.Name], n)
		if root {
			continue
		}
		ev := common.Evidence(file, "cargo-lock", fmt.Sprintf("/package/%d", i), data)
		component := model.Component{ID: ref, Kind: "package", Name: pkg.Name, Version: pkg.Version, PURL: cargoPURL(pkg.Name, pkg.Version, pkg.Source), Hashes: common.HexSHA256(pkg.Checksum), Evidence: []model.Evidence{ev}}
		if pkg.Source == "" {
			component.Kind = "application"
			component.PURL = ""
		}
		doc.Components = append(doc.Components, component)
		kind, source, revision := cargoSource(pkg.Source)
		if kind == "local" {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
		} else if source != "" {
			clean := safeurl.Clean(source)
			if clean == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: pkg.Name})
			} else {
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: kind, SafeURL: clean, Revision: revision, Status: "declared", Evidence: ev})
			}
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: pkg.Name})
		}
	}
	if rootName != "" && rootCount != 1 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies", Name: "Cargo root package"})
	}
	resolve := func(spec string) node {
		fields := strings.Fields(spec)
		if len(fields) == 0 {
			return node{}
		}
		name := fields[0]
		candidates := byName[name]
		if len(fields) >= 2 {
			filtered := []node{}
			for _, candidate := range candidates {
				if candidate.pkg.Version == fields[1] {
					filtered = append(filtered, candidate)
				}
			}
			candidates = filtered
		}
		if len(fields) >= 3 {
			source := strings.Trim(strings.Join(fields[2:], " "), "()")
			filtered := []node{}
			for _, candidate := range candidates {
				if candidate.pkg.Source == source {
					filtered = append(filtered, candidate)
				}
			}
			candidates = filtered
		}
		if len(candidates) == 1 {
			return candidates[0]
		}
		code := "unresolved_dependency"
		if len(candidates) > 1 {
			code = "ambiguous_dependency"
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name})
		return node{}
	}
	for _, n := range nodes {
		for _, spec := range n.pkg.Dependencies {
			to := resolve(spec)
			if to.ref == "" || to.ref == "root" {
				continue
			}
			condition := "feature_or_target_unselected"
			if n.root {
				condition = cargoRootCondition(m, to.pkg.Name)
			}
			if condition != "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: to.pkg.Name})
			}
			kind := "depends_on"
			if n.root {
				kind = "direct"
			}
			doc.Edges = append(doc.Edges, model.Edge{From: n.ref, To: to.ref, Kind: kind, Condition: condition, Evidence: common.Evidence(file, "cargo-lock", "/package/dependencies", data)})
		}
	}
	// Cargo.lock is a union across features and targets. The selected build
	// graph requires Cargo's resolver and cannot be inferred from this file.
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: "feature and target selection"})
	common.Finalize(&doc)
	return doc, nil
}

func cargoSource(raw string) (string, string, string) {
	if raw == "" {
		return "local", "", ""
	}
	if strings.HasPrefix(raw, "registry+") {
		return "declared_registry", strings.TrimPrefix(raw, "registry+"), ""
	}
	if strings.HasPrefix(raw, "sparse+") {
		return "declared_registry", strings.TrimPrefix(raw, "sparse+"), ""
	}
	if strings.HasPrefix(raw, "git+") {
		urlText := strings.TrimPrefix(raw, "git+")
		revision := ""
		if hash := strings.LastIndex(urlText, "#"); hash >= 0 {
			revision = urlText[hash+1:]
			urlText = urlText[:hash]
		}
		if !commitHash(revision) {
			revision = ""
		}
		return "vcs", urlText, revision
	}
	return "", "", ""
}

func cargoPURL(name, version, source string) string {
	if name == "" || version == "" {
		return ""
	}
	switch source {
	case "registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/":
		return "pkg:cargo/" + url.PathEscape(name) + "@" + url.PathEscape(version)
	default:
		return ""
	}
}

func commitHash(value string) bool {
	if len(value) < 7 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

func cargoRootCondition(m manifest, name string) string {
	if spec, ok := m.Dependencies[name]; ok {
		if cargoOptional(spec) {
			return "optional"
		}
		return ""
	}
	if _, ok := m.DevDependencies[name]; ok {
		return "group=dev"
	}
	if _, ok := m.BuildDependencies[name]; ok {
		return "group=build"
	}
	for target, group := range m.Target {
		if _, ok := group.Dependencies[name]; ok {
			return "target=" + target
		}
		if _, ok := group.DevDependencies[name]; ok {
			return "target=" + target + " && group=dev"
		}
		if _, ok := group.BuildDependencies[name]; ok {
			return "target=" + target + " && group=build"
		}
	}
	return "manifest_dependency_unmatched"
}

func cargoOptional(spec any) bool {
	if table, ok := spec.(map[string]any); ok {
		optional, _ := table["optional"].(bool)
		return optional
	}
	return false
}
