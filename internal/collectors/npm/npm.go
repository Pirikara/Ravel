package npm

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/licensing"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

type lockfile struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]lockPackage `json:"packages"`
}

type lockPackage struct {
	License              json.RawMessage   `json:"license"`
	Licenses             json.RawMessage   `json:"licenses"`
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Patched              *lockPatch        `json:"patched"`
}

type lockPatch struct {
	Path      string `json:"path"`
	Integrity string `json:"integrity"`
}

type item struct {
	location string
	data     lockPackage
	ref      string
}

var gitCommit = regexp.MustCompile(`^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)

// Collect supports npm lockfile versions 1 through 4.
func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid npm lockfile: %w", err)
	}
	if lock.LockfileVersion == 1 {
		return collectV1(file, project, data)
	}
	if lock.LockfileVersion != 2 && lock.LockfileVersion != 3 && lock.LockfileVersion != 4 || lock.Packages == nil {
		return model.Document{}, fmt.Errorf("unsupported npm lockfile version or missing packages map")
	}
	doc := common.NewDocument(file, project, "npm", data)
	entries := map[string]*item{}
	links := map[string]string{}
	for location, meta := range lock.Packages {
		if location == "" {
			continue
		}
		if meta.Link {
			// Resolve links only through records already present in this lock.
			// No filesystem lookup or package code execution is needed.
			links[location] = ""
			if localLockLocation(meta.Resolved) {
				links[location] = meta.Resolved
			}
			continue
		}
		name := meta.Name
		if name == "" {
			name = nameFromLocation(location)
		}
		if name == "" || meta.Version == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: location})
			continue
		}
		ref := "npm:" + common.ID(location+"|"+name+"|"+meta.Version)
		pointer := "/packages/" + escapePointer(location)
		ev := common.Evidence(file, "npm-lock", pointer, data)
		component := model.Component{
			ID: ref, Kind: "package", Name: name, Version: meta.Version,
			Licenses: append(licensing.JSON(meta.License, ev, pointer+"/license", false), licensing.JSON(meta.Licenses, ev, pointer+"/licenses", false)...),
			Hashes:   common.Integrity(meta.Integrity),
			Evidence: []model.Evidence{ev},
		}
		if meta.Patched != nil {
			patch, issue := inspectPatch(file, location, meta.Patched, common.Evidence(file, "npm-lock", pointer+"/patched", data))
			component.Patches = []model.Patch{patch}
			if issue != nil {
				doc.Coverage.Issues = append(doc.Coverage.Issues, *issue)
			}
			if lock.LockfileVersion < 4 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsupported_lock_feature", Name: location})
			}
		}
		if common.DefaultNpmRegistry(meta.Resolved) {
			component.PURL = common.NpmPURL(name, meta.Version)
		}
		entries[location] = &item{location: location, data: meta, ref: ref}
		doc.Components = append(doc.Components, component)
		if localLockLocation(location) && !strings.Contains("/"+location+"/", "/node_modules/") {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", LocalPath: location, Status: "declared", Evidence: ev})
		} else {
			addOrigin(&doc, ref, name, meta.Version, meta.Resolved, ev)
		}
	}
	for location := range links {
		if followLockedLink(entries, links, location) == nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: location})
		}
	}
	root, ok := lock.Packages[""]
	if !ok {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	} else if root.Name != "" {
		doc.Root = &model.ProjectIdentity{Name: root.Name, Version: root.Version,
			Evidence: common.Evidence(file, "npm-lock", "/packages", data), Licenses: append(licensing.JSON(root.License, common.Evidence(file, "npm-lock", "", data), "/packages//license", false), licensing.JSON(root.Licenses, common.Evidence(file, "npm-lock", "", data), "/packages//licenses", false)...)}
	}
	manifestPath := filepath.Join(filepath.Dir(file), "package.json")
	if manifestData, err := os.ReadFile(manifestPath); err == nil {
		doc.Sources = append(doc.Sources, manifestPath)
		var manifest struct {
			Name                 string            `json:"name"`
			Version              string            `json:"version"`
			Dependencies         map[string]string `json:"dependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
		}
		manifestErr := json.Unmarshal(manifestData, &manifest)
		if manifestErr == nil && manifest.Name != "" {
			priorRoot := doc.Root
			doc.Root = &model.ProjectIdentity{Name: manifest.Name, Version: manifest.Version,
				Evidence: common.Evidence(manifestPath, "npm-manifest", "/name", manifestData), Licenses: licensing.JSONFields(manifestData, common.Evidence(manifestPath, "npm-manifest", "", manifestData))}
			common.CollectNodeDevelopment(&doc, "root", manifestData, common.Evidence(manifestPath, "npm-manifest", "", manifestData))
			if priorRoot != nil && priorRoot.Name == doc.Root.Name && priorRoot.Version == doc.Root.Version {
				doc.Root.Licenses = append(doc.Root.Licenses, priorRoot.Licenses...)
			}
		}
		if ok && (manifestErr != nil ||
			!maps.Equal(manifest.Dependencies, root.Dependencies) ||
			!maps.Equal(manifest.DevDependencies, root.DevDependencies) ||
			!maps.Equal(manifest.OptionalDependencies, root.OptionalDependencies) ||
			!maps.Equal(manifest.PeerDependencies, root.PeerDependencies) ||
			manifest.Name != "" && root.Name != "" && manifest.Name != root.Name ||
			manifest.Version != "" && root.Version != "" && manifest.Version != root.Version) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified"})
		}
	}
	if lock.LockfileVersion == 4 {
		verifyPatchManifest(&doc, file, entries)
	}
	seen := map[string]bool{}
	addEdges := func(from, location, kind string, deps map[string]string) {
		for name, required := range deps {
			to := resolve(entries, links, location, name)
			if to == nil {
				if kind != "optional" && kind != "peer_requirement" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
				}
				continue
			}
			matches, verified := matchesNpmRequirementAt(required, to, location)
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
			edge := model.Edge{From: from, To: to.ref, Kind: kind, Evidence: common.Evidence(file, "npm-lock", "/packages/"+escapePointer(location), data)}
			if kind == "optional" || kind == "peer_requirement" {
				edge.Condition = kind
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: name})
			}
			doc.Edges = append(doc.Edges, edge)
		}
	}
	if ok {
		addEdges("root", "", "direct", root.Dependencies)
		addEdges("root", "", "direct_dev", root.DevDependencies)
		addEdges("root", "", "optional", root.OptionalDependencies)
		addEdges("root", "", "peer_requirement", root.PeerDependencies)
	}
	for _, entry := range entries {
		addEdges(entry.ref, entry.location, "depends_on", entry.data.Dependencies)
		if localLockLocation(entry.location) && !strings.Contains("/"+entry.location+"/", "/node_modules/") {
			addEdges(entry.ref, entry.location, "direct_dev", entry.data.DevDependencies)
		}
		addEdges(entry.ref, entry.location, "optional", entry.data.OptionalDependencies)
		addEdges(entry.ref, entry.location, "peer_requirement", entry.data.PeerDependencies)
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

func nameFromLocation(location string) string {
	idx := strings.LastIndex(location, "node_modules/")
	if idx < 0 {
		return ""
	}
	name := location[idx+len("node_modules/"):]
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}
	return strings.SplitN(name, "/", 2)[0]
}

func resolve(entries map[string]*item, links map[string]string, location, name string) *item {
	base := location
	for {
		if path.Base(base) != "node_modules" {
			candidate := path.Join(base, "node_modules", name)
			if entry := entries[candidate]; entry != nil {
				return entry
			}
			if _, exists := links[candidate]; exists {
				return followLockedLink(entries, links, candidate)
			}
		}
		if base == "" {
			return nil
		}
		base = path.Dir(base)
		if base == "." {
			base = ""
		}
	}
}

func localLockLocation(location string) bool {
	return location != "" && location != "." && path.Clean(location) == location &&
		!path.IsAbs(location) && location != ".." && !strings.HasPrefix(location, "../") &&
		!strings.ContainsAny(location, ":\\\x00\r\n")
}

func followLockedLink(entries map[string]*item, links map[string]string, location string) *item {
	seen := map[string]bool{}
	for !seen[location] {
		seen[location] = true
		if entry := entries[location]; entry != nil {
			return entry
		}
		target, exists := links[location]
		if !exists || target == "" {
			return nil
		}
		location = target
	}
	return nil
}

func addOrigin(doc *model.Document, ref, name, version, raw string, ev model.Evidence) {
	if raw == "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: ref})
		return
	}
	if raw == "registry.npmjs.org" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "source_unresolved", Name: ref})
		return
	}
	if strings.HasPrefix(raw, "file:") || strings.HasPrefix(raw, "link:") {
		local := strings.TrimPrefix(strings.TrimPrefix(raw, "file:"), "link:")
		if strings.HasPrefix(local, "//") || strings.ContainsAny(local, "?#@") {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: ref})
			return
		}
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", LocalPath: path.Clean(local), Status: "declared", Evidence: ev})
		return
	}
	kind := "download_url"
	revision := ""
	if strings.HasPrefix(raw, "git+") {
		kind = "vcs"
		raw = strings.TrimPrefix(raw, "git+")
		if parsed, err := url.Parse(raw); err == nil && gitCommit.MatchString(parsed.Fragment) {
			revision = strings.ToLower(parsed.Fragment)
		}
	}
	clean := safeurl.Clean(raw)
	if clean == "" {
		clean = safeurl.CleanNpmTarball(raw, name, version)
	}
	if clean == "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: ref})
		return
	}
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: kind, SafeURL: clean, Revision: revision, Status: "declared", Evidence: ev})
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
