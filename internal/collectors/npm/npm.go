package npm

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

type lockfile struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]lockPackage `json:"packages"`
}

type lockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type item struct {
	location string
	data     lockPackage
	ref      string
}

var gitCommit = regexp.MustCompile(`^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)

// Collect supports npm lockfile versions 1, 2, and 3.
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
	if lock.LockfileVersion != 2 && lock.LockfileVersion != 3 || lock.Packages == nil {
		return model.Document{}, fmt.Errorf("unsupported npm lockfile version or missing packages map")
	}
	doc := common.NewDocument(file, project, "npm", data)
	entries := map[string]*item{}
	for location, meta := range lock.Packages {
		if location == "" {
			continue
		}
		if meta.Link {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: location})
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
			Hashes:   common.Integrity(meta.Integrity),
			Evidence: []model.Evidence{ev},
		}
		if common.DefaultNpmRegistry(meta.Resolved) {
			component.PURL = common.NpmPURL(name, meta.Version)
		}
		entries[location] = &item{location: location, data: meta, ref: ref}
		doc.Components = append(doc.Components, component)
		addOrigin(&doc, ref, meta.Resolved, ev)
	}
	root, ok := lock.Packages[""]
	if !ok {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	}
	seen := map[string]bool{}
	addEdges := func(from, location, kind string, deps map[string]string) {
		for name := range deps {
			to := resolve(entries, location, name)
			if to == "" {
				if kind != "optional" && kind != "peer_requirement" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
				}
				continue
			}
			key := from + "\x00" + to + "\x00" + kind
			if seen[key] {
				continue
			}
			seen[key] = true
			edge := model.Edge{From: from, To: to, Kind: kind, Evidence: common.Evidence(file, "npm-lock", "/packages/"+escapePointer(location), data)}
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
	}
	for _, entry := range entries {
		addEdges(entry.ref, entry.location, "depends_on", entry.data.Dependencies)
		addEdges(entry.ref, entry.location, "optional", entry.data.OptionalDependencies)
		addEdges(entry.ref, entry.location, "peer_requirement", entry.data.PeerDependencies)
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

func resolve(entries map[string]*item, location, name string) string {
	base := location
	for {
		candidate := path.Join(base, "node_modules", name)
		if entry := entries[candidate]; entry != nil {
			return entry.ref
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

func addOrigin(doc *model.Document, ref, raw string, ev model.Evidence) {
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
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: ref})
		return
	}
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: kind, SafeURL: clean, Revision: revision, Status: "declared", Evidence: ev})
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
