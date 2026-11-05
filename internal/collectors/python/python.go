package python

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

type dependency struct {
	Name    string   `toml:"name"`
	Version string   `toml:"version"`
	Marker  string   `toml:"marker"`
	Index   string   `toml:"index"`
	Source  uvSource `toml:"source"`
}

type uvSource struct {
	Registry  string `toml:"registry"`
	Git       string `toml:"git"`
	URL       string `toml:"url"`
	Editable  string `toml:"editable"`
	Virtual   string `toml:"virtual"`
	Directory string `toml:"directory"`
	Path      string `toml:"path"`
}

type artifact struct {
	URL    string            `toml:"url"`
	Path   string            `toml:"path"`
	Hash   string            `toml:"hash"`
	Hashes map[string]string `toml:"hashes"`
}

type uvPackage struct {
	Name         string                  `toml:"name"`
	Version      string                  `toml:"version"`
	Source       uvSource                `toml:"source"`
	Marker       string                  `toml:"marker"`
	Dependencies []dependency            `toml:"dependencies"`
	Optional     map[string][]dependency `toml:"optional-dependencies"`
	Groups       map[string][]dependency `toml:"dependency-groups"`
	Dev          []dependency            `toml:"dev-dependencies"`
	Sdist        artifact                `toml:"sdist"`
	Wheels       []artifact              `toml:"wheels"`
}

type uvLock struct {
	Version           int         `toml:"version"`
	ResolutionMarkers []string    `toml:"resolution-markers"`
	Packages          []uvPackage `toml:"package"`
}

type pyVCS struct {
	URL      string `toml:"url"`
	Path     string `toml:"path"`
	CommitID string `toml:"commit-id"`
}

type pyPackage struct {
	Name         string       `toml:"name"`
	Version      string       `toml:"version"`
	Marker       string       `toml:"marker"`
	Index        string       `toml:"index"`
	Dependencies []dependency `toml:"dependencies"`
	VCS          pyVCS        `toml:"vcs"`
	Directory    artifact     `toml:"directory"`
	Archive      artifact     `toml:"archive"`
	Sdist        artifact     `toml:"sdist"`
	Wheels       []artifact   `toml:"wheels"`
}

type pyLock struct {
	LockVersion  string      `toml:"lock-version"`
	Environments []string    `toml:"environments"`
	Packages     []pyPackage `toml:"packages"`
}

type node struct {
	ref, name, version, marker, source string
	deps                               []dependency
	optional                           map[string][]dependency
	groups                             map[string][]dependency
	dev                                []dependency
	root                               bool
}

var normalizeSeparators = regexp.MustCompile(`[-_.]+`)
var commitID = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

func normalized(name string) string {
	return normalizeSeparators.ReplaceAllString(strings.ToLower(name), "-")
}

func purl(name, version string) string {
	if name == "" || version == "" {
		return ""
	}
	return "pkg:pypi/" + url.PathEscape(normalized(name)) + "@" + common.PURLVersion(version)
}

func defaultPyPIIndex(raw string) bool {
	clean := strings.TrimSuffix(safeurl.Clean(raw), "/")
	return clean == "https://pypi.org/simple" || clean == "https://pypi.python.org/simple"
}

func CollectUV(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock uvLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid uv.lock: %w", err)
	}
	if lock.Version != 1 || len(lock.Packages) == 0 {
		return model.Document{}, fmt.Errorf("unsupported uv.lock version or empty package list")
	}
	doc := common.NewDocument(file, project, "uv", data)
	globalCondition := ""
	if len(lock.ResolutionMarkers) > 0 {
		globalCondition = "resolution=" + strings.Join(lock.ResolutionMarkers, " || ")
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: "resolution markers"})
	}
	nodes := make([]node, 0, len(lock.Packages))
	for i, pkg := range lock.Packages {
		if pkg.Name == "" {
			return model.Document{}, fmt.Errorf("uv.lock package %d has no name", i)
		}
		root := pkg.Source.Editable == "." || pkg.Source.Virtual == "."
		ref := "uv:" + common.ID(fmt.Sprintf("%d|%s|%s", i, pkg.Name, pkg.Version))
		if root {
			ref = "root"
		}
		nodes = append(nodes, node{ref: ref, name: normalized(pkg.Name), version: pkg.Version, marker: pkg.Marker, source: uvSourceKey(pkg.Source), deps: pkg.Dependencies, optional: pkg.Optional, groups: pkg.Groups, dev: pkg.Dev, root: root})
		if root {
			continue
		}
		ev := common.Evidence(file, "uv-lock", fmt.Sprintf("/package/%d", i), data)
		component := model.Component{ID: ref, Kind: "package", Name: pkg.Name, Version: pkg.Version, Evidence: []model.Evidence{ev}}
		if defaultPyPIIndex(pkg.Source.Registry) {
			component.PURL = purl(pkg.Name, pkg.Version)
		}
		if pkg.Sdist.URL == "" && len(pkg.Wheels) == 1 {
			component.Hashes = artifactHashes(pkg.Wheels[0])
		}
		if len(pkg.Wheels) == 0 && pkg.Sdist.URL != "" {
			component.Hashes = artifactHashes(pkg.Sdist)
		}
		doc.Components = append(doc.Components, component)
		switch {
		case pkg.Source.Registry != "":
			addURLOrigin(&doc, ref, "declared_registry", pkg.Source.Registry, "", ev, pkg.Name)
		case pkg.Source.Git != "":
			clean, revision := gitURL(pkg.Source.Git)
			addOrigin(&doc, ref, "vcs", clean, revision, ev, pkg.Name, pkg.Source.Git != "")
		case pkg.Source.URL != "":
			addURLOrigin(&doc, ref, "download_url", pkg.Source.URL, "", ev, pkg.Name)
		case pkg.Source.Directory != "" || pkg.Source.Path != "" || pkg.Source.Editable != "" || pkg.Source.Virtual != "":
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
		default:
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: pkg.Name})
		}
		if pkg.Marker != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: pkg.Name})
		}
	}
	addGraph(&doc, nodes, file, data, "uv-lock", globalCondition)
	common.Finalize(&doc)
	return doc, nil
}

func CollectPylock(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock pyLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid pylock.toml: %w", err)
	}
	if lock.LockVersion != "1.0" {
		return model.Document{}, fmt.Errorf("unsupported pylock.toml version %q", lock.LockVersion)
	}
	doc := common.NewDocument(file, project, "pylock", data)
	globalCondition := ""
	if len(lock.Environments) > 0 {
		globalCondition = "environment=" + strings.Join(lock.Environments, " || ")
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: "environments"})
	}
	nodes := make([]node, 0, len(lock.Packages))
	for i, pkg := range lock.Packages {
		if pkg.Name == "" {
			return model.Document{}, fmt.Errorf("pylock.toml package %d has no name", i)
		}
		root := pkg.Directory.Path == "."
		ref := "pylock:" + common.ID(fmt.Sprintf("%d|%s|%s", i, pkg.Name, pkg.Version))
		if root {
			ref = "root"
		}
		nodes = append(nodes, node{ref: ref, name: normalized(pkg.Name), version: pkg.Version, marker: pkg.Marker, source: pkg.Index, deps: pkg.Dependencies, root: root})
		if root {
			continue
		}
		ev := common.Evidence(file, "pylock", fmt.Sprintf("/packages/%d", i), data)
		component := model.Component{ID: ref, Kind: "package", Name: pkg.Name, Version: pkg.Version, Evidence: []model.Evidence{ev}}
		if defaultPyPIIndex(pkg.Index) {
			component.PURL = purl(pkg.Name, pkg.Version)
		}
		if pkg.Archive.URL != "" {
			component.Hashes = artifactHashes(pkg.Archive)
		}
		if pkg.Sdist.URL != "" && len(pkg.Wheels) == 0 {
			component.Hashes = artifactHashes(pkg.Sdist)
		}
		if pkg.Sdist.URL == "" && len(pkg.Wheels) == 1 {
			component.Hashes = artifactHashes(pkg.Wheels[0])
		}
		doc.Components = append(doc.Components, component)
		switch {
		case pkg.VCS.URL != "":
			revision := pkg.VCS.CommitID
			if !commitID.MatchString(revision) {
				revision = ""
			}
			addURLOrigin(&doc, ref, "vcs", pkg.VCS.URL, revision, ev, pkg.Name)
		case pkg.VCS.Path != "" || pkg.Directory.Path != "":
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
		case pkg.Archive.URL != "":
			addURLOrigin(&doc, ref, "download_url", pkg.Archive.URL, "", ev, pkg.Name)
		case pkg.Archive.Path != "":
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
		case pkg.Index != "":
			addURLOrigin(&doc, ref, "declared_registry", pkg.Index, "", ev, pkg.Name)
		default:
			artifacts := append([]artifact{}, pkg.Wheels...)
			if pkg.Sdist.URL != "" || pkg.Sdist.Path != "" {
				artifacts = append(artifacts, pkg.Sdist)
			}
			if len(artifacts) == 0 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: pkg.Name})
			}
			if len(artifacts) > 1 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_source", Name: pkg.Name})
			}
			for _, a := range artifacts {
				if a.URL != "" {
					addURLOrigin(&doc, ref, "download_url", a.URL, "", ev, pkg.Name)
				} else if a.Path != "" {
					doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
				}
			}
		}
		if pkg.Marker != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: pkg.Name})
		}
	}
	addGraph(&doc, nodes, file, data, "pylock", globalCondition)
	common.Finalize(&doc)
	return doc, nil
}

func uvSourceKey(s uvSource) string {
	switch {
	case s.Registry != "":
		return s.Registry
	case s.Git != "":
		return s.Git
	case s.URL != "":
		return s.URL
	case s.Directory != "":
		return s.Directory
	case s.Path != "":
		return s.Path
	case s.Editable != "":
		return s.Editable
	default:
		return s.Virtual
	}
}

func gitURL(raw string) (string, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	revision := u.Fragment
	if !commitID.MatchString(revision) {
		revision = ""
	}
	return safeurl.Clean(raw), revision
}

func addURLOrigin(doc *model.Document, ref, kind, raw, revision string, ev model.Evidence, name string) {
	addOrigin(doc, ref, kind, safeurl.Clean(raw), revision, ev, name, raw != "")
}

func addOrigin(doc *model.Document, ref, kind, clean, revision string, ev model.Evidence, name string, present bool) {
	if clean == "" {
		code := "missing_source"
		if present {
			code = "unsafe_or_invalid_source"
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name})
		return
	}
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: kind, SafeURL: clean, Revision: revision, Status: "declared", Evidence: ev})
}

func artifactHashes(a artifact) []model.Hash {
	if strings.HasPrefix(a.Hash, "sha256:") {
		return common.HexSHA256(strings.TrimPrefix(a.Hash, "sha256:"))
	}
	return common.HexSHA256(a.Hashes["sha256"])
}

func addGraph(doc *model.Document, nodes []node, file string, data []byte, collector, globalCondition string) {
	byName := map[string][]node{}
	rootCount := 0
	for _, n := range nodes {
		if n.root {
			rootCount++
		} else {
			byName[n.name] = append(byName[n.name], n)
		}
	}
	if rootCount == 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	}
	if rootCount > 1 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: "project roots"})
	}
	for _, n := range nodes {
		add := func(deps []dependency, category string) {
			for _, dep := range deps {
				name := normalized(dep.Name)
				candidates := byName[name]
				filtered := make([]node, 0, len(candidates))
				for _, c := range candidates {
					if dep.Version != "" && dep.Version != c.version {
						continue
					}
					if dep.Index != "" && dep.Index != c.source {
						continue
					}
					if source := uvSourceKey(dep.Source); source != "" && source != c.source {
						continue
					}
					filtered = append(filtered, c)
				}
				if len(filtered) > 1 && n.marker != "" {
					matching := []node{}
					for _, c := range filtered {
						if c.marker == n.marker {
							matching = append(matching, c)
						}
					}
					if len(matching) == 1 {
						filtered = matching
					}
				}
				if len(filtered) != 1 {
					code := "unresolved_dependency"
					if len(filtered) > 1 {
						code = "ambiguous_dependency"
					}
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: dep.Name})
					continue
				}
				condition := strings.Join(nonempty(globalCondition, n.marker, dep.Marker, filtered[0].marker, category), " && ")
				if condition != "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: dep.Name})
				}
				ev := common.Evidence(file, collector, "/packages/dependencies/"+dep.Name, data)
				kind := "depends_on"
				if n.root {
					kind = "direct"
				}
				doc.Edges = append(doc.Edges, model.Edge{From: n.ref, To: filtered[0].ref, Kind: kind, Condition: condition, Evidence: ev})
			}
		}
		add(n.deps, "")
		for extra, deps := range n.optional {
			add(deps, "extra="+extra)
		}
		for group, deps := range n.groups {
			add(deps, "group="+group)
		}
		add(n.dev, "group=dev")
	}
}

func nonempty(values ...string) []string {
	out := []string{}
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
