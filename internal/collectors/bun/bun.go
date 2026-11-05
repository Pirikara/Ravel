package bun

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	semver "github.com/Masterminds/semver/v3"
	"github.com/tailscale/hujson"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

type lockfile struct {
	LockfileVersion *int                       `json:"lockfileVersion"`
	Workspaces      map[string]workspace       `json:"workspaces"`
	Packages        map[string]json.RawMessage `json:"packages"`
}

type workspace struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type metadata struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OS                   string            `json:"os"`
	CPU                  string            `json:"cpu"`
}

type item struct {
	ref, key, name, version, selector, platform, metaPointer string
	meta                                                     metadata
}

var githubRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
var bunGitCommit = regexp.MustCompile(`^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)

func Collect(file, project string) (model.Document, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	standard, err := hujson.Standardize(raw)
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid bun.lock JSONC: %w", err)
	}
	var lock lockfile
	if err := json.Unmarshal(standard, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid bun.lock: %w", err)
	}
	if lock.LockfileVersion == nil || *lock.LockfileVersion < 0 || *lock.LockfileVersion > 2 || lock.Packages == nil {
		return model.Document{}, fmt.Errorf("unsupported bun.lock version or missing packages map")
	}
	doc := common.NewDocument(file, project, "bun", raw)
	if len(lock.Workspaces) > 1 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unreachable_graph", Name: "workspace dependencies"})
	}
	entries := map[string]item{}
	for key, tupleRaw := range lock.Packages {
		var tuple []json.RawMessage
		if err := json.Unmarshal(tupleRaw, &tuple); err != nil || len(tuple) == 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: key})
			continue
		}
		var identifier string
		if err := json.Unmarshal(tuple[0], &identifier); err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: key})
			continue
		}
		name, selector, ok := splitIdentifier(identifier)
		if !ok {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: key})
			continue
		}
		if strings.HasPrefix(selector, "root:") || strings.HasPrefix(selector, "workspace:") || strings.HasPrefix(selector, "link:") || strings.HasPrefix(selector, "file:") {
			continue
		}
		version := selector
		if _, err := semver.StrictNewVersion(selector); err != nil {
			version = ""
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "package_version_unavailable", Name: name})
		}
		var meta metadata
		var integrity, source string
		metaPointer := "/packages/" + escapePointer(key)
		for index, field := range tuple[1:] {
			if len(field) == 0 {
				continue
			}
			if field[0] == '{' {
				if err := json.Unmarshal(field, &meta); err != nil {
					return model.Document{}, fmt.Errorf("invalid bun.lock package metadata: %w", err)
				}
				metaPointer = "/packages/" + escapePointer(key) + "/" + strconv.Itoa(index+1)
				continue
			}
			var value string
			if json.Unmarshal(field, &value) != nil || value == "" {
				continue
			}
			if strings.HasPrefix(value, "sha") && strings.Contains(value, "-") {
				integrity = value
			} else if strings.Contains(value, "://") {
				source = value
			}
		}
		ref := "bun:" + common.ID(key+"|"+identifier)
		ev := common.Evidence(file, "bun-lock", "/packages/"+escapePointer(key), raw)
		component := model.Component{ID: ref, Kind: "package", Name: name, Version: version, Evidence: []model.Evidence{ev}, Hashes: common.Integrity(integrity)}
		if version != "" && common.DefaultNpmRegistry(source) {
			component.PURL = common.NpmPURL(name, version)
		} else if version != "" && source == "" {
			component.PURL = common.NpmPURL(name, version)
			component.PURLBasis = "ecosystem_inferred"
		}
		if meta.OS != "" || meta.CPU != "" {
			component.Platform = strings.Trim(strings.Join([]string{meta.OS, meta.CPU}, "/"), "/")
		}
		doc.Components = append(doc.Components, component)
		entries[key] = item{ref: ref, key: key, name: name, version: version, selector: selector, platform: component.Platform, metaPointer: metaPointer, meta: meta}
		addOrigin(&doc, ref, selector, source, ev)
	}
	seen := map[string]bool{}
	addEdges := func(from, location, pointer string, deps map[string]string, kind string) {
		for name, required := range deps {
			to, ok := resolveBun(entries, location, name)
			if !ok {
				if kind != "optional" && kind != "peer_requirement" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
				}
				continue
			}
			matches, verified := matchesBunRequirement(required, to)
			if !matches {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
				continue
			}
			if !verified {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dependency_constraint_unverified", Name: name})
			}
			key := from + "\x00" + to.ref + "\x00" + kind
			if seen[key] {
				continue
			}
			seen[key] = true
			field := "dependencies"
			switch kind {
			case "direct_dev":
				field = "devDependencies"
			case "optional":
				field = "optionalDependencies"
			case "peer_requirement":
				field = "peerDependencies"
			}
			edge := model.Edge{From: from, To: to.ref, Kind: kind, Evidence: common.Evidence(file, "bun-lock", pointer+"/"+field+"/"+escapePointer(name), raw)}
			if kind == "optional" || kind == "peer_requirement" {
				edge.Condition = kind
			}
			if to.platform != "" {
				if edge.Condition != "" {
					edge.Condition += ";"
				}
				edge.Condition += "platform=" + to.platform
			}
			if edge.Condition != "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: name})
			}
			doc.Edges = append(doc.Edges, edge)
		}
	}
	root, ok := lock.Workspaces[""]
	if !ok {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	} else {
		if root.Name != "" {
			doc.Root = &model.ProjectIdentity{Name: root.Name, Version: root.Version,
				Evidence: common.Evidence(file, "bun-lock", "/workspaces/", raw)}
		}
		manifestPath := filepath.Join(filepath.Dir(file), "package.json")
		if manifestData, err := os.ReadFile(manifestPath); err == nil {
			doc.Sources = append(doc.Sources, manifestPath)
			var manifest workspace
			manifestErr := json.Unmarshal(manifestData, &manifest)
			if manifestErr == nil && manifest.Name != "" {
				doc.Root = &model.ProjectIdentity{Name: manifest.Name, Version: manifest.Version,
					Evidence: common.Evidence(manifestPath, "bun-manifest", "/name", manifestData)}
			}
			if manifestErr != nil ||
				!maps.Equal(manifest.Dependencies, root.Dependencies) ||
				!maps.Equal(manifest.DevDependencies, root.DevDependencies) ||
				!maps.Equal(manifest.OptionalDependencies, root.OptionalDependencies) ||
				!maps.Equal(manifest.PeerDependencies, root.PeerDependencies) ||
				manifest.Name != "" && root.Name != "" && manifest.Name != root.Name ||
				manifest.Version != "" && root.Version != "" && manifest.Version != root.Version {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified"})
			}
		}
		addEdges("root", "", "/workspaces/", root.Dependencies, "direct")
		addEdges("root", "", "/workspaces/", root.DevDependencies, "direct_dev")
		addEdges("root", "", "/workspaces/", root.OptionalDependencies, "optional")
		addEdges("root", "", "/workspaces/", root.PeerDependencies, "peer_requirement")
	}
	for _, entry := range entries {
		addEdges(entry.ref, entry.key, entry.metaPointer, entry.meta.Dependencies, "depends_on")
		addEdges(entry.ref, entry.key, entry.metaPointer, entry.meta.OptionalDependencies, "optional")
		addEdges(entry.ref, entry.key, entry.metaPointer, entry.meta.PeerDependencies, "peer_requirement")
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

func resolveBun(entries map[string]item, location, name string) (item, bool) {
	base := location
	for {
		candidate := name
		if base != "" {
			candidate = base + "/" + name
		}
		if entry, ok := entries[candidate]; ok {
			return entry, true
		}
		if base == "" {
			return item{}, false
		}
		base = parentBunKey(entries, base)
	}
}

func parentBunKey(entries map[string]item, location string) string {
	for index := strings.LastIndex(location, "/"); index >= 0; index = strings.LastIndex(location[:index], "/") {
		candidate := location[:index]
		if _, ok := entries[candidate]; ok {
			return candidate
		}
	}
	return ""
}

func matchesBunRequirement(required string, entry item) (matches, verified bool) {
	if required != "" && (required == entry.version || required == entry.selector) {
		return true, true
	}
	if strings.HasPrefix(required, "npm:") {
		name, constraint, ok := splitIdentifier(strings.TrimPrefix(required, "npm:"))
		if !ok || name != entry.name {
			return false, true
		}
		required = constraint
	}
	if entry.version == "" {
		return true, false
	}
	version, err := semver.StrictNewVersion(entry.version)
	if err != nil {
		return true, false
	}
	constraint, err := semver.NewConstraint(required)
	if err != nil {
		return true, false
	}
	return constraint.Check(version), true
}

func splitIdentifier(s string) (string, string, bool) {
	start := 1
	if strings.HasPrefix(s, "@") {
		slash := strings.IndexByte(s, '/')
		if slash < 0 {
			return "", "", false
		}
		start = slash + 1
	}
	separator := strings.IndexByte(s[start:], '@')
	if separator < 0 {
		return "", "", false
	}
	separator += start
	if separator == 0 || separator == len(s)-1 {
		return "", "", false
	}
	return s[:separator], s[separator+1:], true
}

func addOrigin(doc *model.Document, ref, version, source string, ev model.Evidence) {
	if source == "" && (strings.HasPrefix(version, "git+") || strings.HasPrefix(version, "git://") || strings.HasPrefix(version, "ssh://") || strings.HasPrefix(version, "https://") || strings.HasPrefix(version, "http://")) {
		source = version
	}
	if source != "" {
		clean := safeurl.Clean(strings.TrimPrefix(source, "git+"))
		if clean == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: ref})
			return
		}
		kind := "download_url"
		revision := ""
		if strings.HasPrefix(source, "git+") || strings.HasPrefix(source, "git://") || strings.HasPrefix(source, "ssh://") {
			kind = "vcs"
			if parsed, err := url.Parse(strings.TrimPrefix(source, "git+")); err == nil && bunGitCommit.MatchString(parsed.Fragment) {
				revision = strings.ToLower(parsed.Fragment)
			}
		}
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: kind, SafeURL: clean, Revision: revision, Status: "declared", Evidence: ev})
		return
	}
	if strings.HasPrefix(version, "github:") {
		repo, revision, _ := strings.Cut(strings.TrimPrefix(version, "github:"), "#")
		if !bunGitCommit.MatchString(revision) {
			revision = ""
		}
		parts := strings.SplitN(repo, "/", 2)
		if !githubRepository.MatchString(repo) || parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: ref})
			return
		}
		clean := safeurl.Clean("https://github.com/" + repo)
		if clean != "" {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "vcs", SafeURL: clean, Revision: strings.ToLower(revision), Status: "declared", Evidence: ev})
			return
		}
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: ref})
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
