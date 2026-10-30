package bun

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/tailscale/hujson"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

type lockfile struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Workspaces      map[string]workspace       `json:"workspaces"`
	Packages        map[string]json.RawMessage `json:"packages"`
}

type workspace struct {
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
	ref  string
	meta metadata
	name string
}

var githubRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

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
	if lock.LockfileVersion != 1 || lock.Packages == nil {
		return model.Document{}, fmt.Errorf("unsupported bun.lock version or missing packages map")
	}
	doc := common.NewDocument(file, project, "bun", raw)
	if len(lock.Workspaces) > 1 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unreachable_graph", Name: "workspace dependencies"})
	}
	byName := map[string][]item{}
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
		name, version, ok := splitIdentifier(identifier)
		if !ok {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: key})
			continue
		}
		if strings.HasPrefix(version, "root:") || strings.HasPrefix(version, "workspace:") || strings.HasPrefix(version, "link:") || strings.HasPrefix(version, "file:") {
			continue
		}
		var meta metadata
		var integrity, source string
		for _, field := range tuple[1:] {
			if len(field) == 0 {
				continue
			}
			if field[0] == '{' {
				_ = json.Unmarshal(field, &meta)
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
		if !strings.Contains(version, ":") && common.DefaultNpmRegistry(source) {
			component.PURL = common.NpmPURL(name, version)
		}
		if meta.OS != "" || meta.CPU != "" {
			component.Platform = strings.Trim(strings.Join([]string{meta.OS, meta.CPU}, "/"), "/")
		}
		doc.Components = append(doc.Components, component)
		byName[name] = append(byName[name], item{ref: ref, meta: meta, name: name})
		addOrigin(&doc, ref, version, source, ev)
	}
	seen := map[string]bool{}
	addEdges := func(from string, deps map[string]string, kind string) {
		for name := range deps {
			matches := byName[name]
			if len(matches) != 1 {
				code := "unresolved_dependency"
				if len(matches) > 1 {
					code = "ambiguous_dependency"
				}
				if kind != "optional" && kind != "peer_requirement" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name})
				}
				continue
			}
			to := matches[0].ref
			key := from + "\x00" + to + "\x00" + kind
			if seen[key] {
				continue
			}
			seen[key] = true
			edge := model.Edge{From: from, To: to, Kind: kind, Evidence: common.Evidence(file, "bun-lock", "/packages", raw)}
			if kind == "optional" || kind == "peer_requirement" {
				edge.Condition = kind
			}
			for _, c := range doc.Components {
				if c.ID == to && c.Platform != "" {
					edge.Condition = "platform=" + c.Platform
				}
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
		addEdges("root", root.Dependencies, "direct")
		addEdges("root", root.DevDependencies, "direct_dev")
		addEdges("root", root.OptionalDependencies, "optional")
		addEdges("root", root.PeerDependencies, "peer_requirement")
	}
	for _, items := range byName {
		for _, entry := range items {
			addEdges(entry.ref, entry.meta.Dependencies, "depends_on")
			addEdges(entry.ref, entry.meta.OptionalDependencies, "optional")
			addEdges(entry.ref, entry.meta.PeerDependencies, "peer_requirement")
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func splitIdentifier(s string) (string, string, bool) {
	last := strings.LastIndex(s, "@")
	if last <= 0 || last == len(s)-1 {
		return "", "", false
	}
	return s[:last], s[last+1:], true
}

func addOrigin(doc *model.Document, ref, version, source string, ev model.Evidence) {
	if source != "" {
		clean := safeurl.Clean(strings.TrimPrefix(source, "git+"))
		if clean == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: ref})
			return
		}
		kind := "download_url"
		if strings.HasPrefix(source, "git+") {
			kind = "vcs"
		}
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: kind, SafeURL: clean, Status: "declared", Evidence: ev})
		return
	}
	if strings.HasPrefix(version, "github:") {
		repo := strings.SplitN(strings.TrimPrefix(version, "github:"), "#", 2)[0]
		if !githubRepository.MatchString(repo) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: ref})
			return
		}
		clean := safeurl.Clean("https://github.com/" + repo)
		if clean != "" {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "vcs", SafeURL: clean, Status: "declared", Evidence: ev})
			return
		}
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: ref})
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
