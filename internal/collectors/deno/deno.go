package deno

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tailscale/hujson"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

type lockfile struct {
	Version    string                  `json:"version"`
	Specifiers map[string]string       `json:"specifiers"`
	JSR        map[string]packageEntry `json:"jsr"`
	NPM        map[string]packageEntry `json:"npm"`
	Remote     map[string]string       `json:"remote"`
	Workspace  struct {
		Dependencies []string `json:"dependencies"`
	} `json:"workspace"`
}

type packageEntry struct {
	Integrity    string   `json:"integrity"`
	Dependencies []string `json:"dependencies"`
}

type configFile struct {
	Imports map[string]string `json:"imports"`
}

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type item struct {
	ref     string
	name    string
	version string
	deps    []string
	kind    string
}

// Collect emits the package closure reachable from config imports and workspace
// dependencies. Source-level imports require a separate module graph analysis, so
// the static result explicitly remains partial.
func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid deno.lock: %w", err)
	}
	if lock.Version != "4" && lock.Version != "5" {
		return model.Document{}, fmt.Errorf("unsupported deno.lock version %q", lock.Version)
	}
	doc := common.NewDocument(file, project, "deno", data)
	base := filepath.Dir(file)
	var roots []string
	for _, name := range []string{"deno.json", "deno.jsonc"} {
		configData, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			continue
		}
		doc.Sources = append(doc.Sources, filepath.Join(base, name))
		standard, err := hujson.Standardize(configData)
		if err != nil {
			return model.Document{}, fmt.Errorf("invalid %s: %w", name, err)
		}
		var config configFile
		if err := json.Unmarshal(standard, &config); err != nil {
			return model.Document{}, fmt.Errorf("invalid %s: %w", name, err)
		}
		for _, value := range config.Imports {
			roots = append(roots, value)
		}
		break
	}
	if packageData, err := os.ReadFile(filepath.Join(base, "package.json")); err == nil {
		doc.Sources = append(doc.Sources, filepath.Join(base, "package.json"))
		var pkg packageJSON
		if json.Unmarshal(packageData, &pkg) == nil {
			for name, constraint := range pkg.Dependencies {
				roots = append(roots, "npm:"+name+"@"+constraint)
			}
			for name, constraint := range pkg.DevDependencies {
				roots = append(roots, "npm:"+name+"@"+constraint)
			}
		}
	}
	roots = append(roots, lock.Workspace.Dependencies...)
	if len(roots) == 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	}
	items := map[string]item{}
	byName := map[string][]string{}
	for key, meta := range lock.JSR {
		name, version, ok := splitNameVersion(key)
		if !ok {
			continue
		}
		ref := "deno:jsr:" + common.ID(key)
		items["jsr:"+key] = item{ref: ref, name: name, version: version, deps: meta.Dependencies, kind: "jsr"}
		byName["jsr:"+name] = append(byName["jsr:"+name], "jsr:"+key)
	}
	for key, meta := range lock.NPM {
		name, version, ok := splitNameVersion(key)
		if !ok {
			continue
		}
		version = strings.SplitN(version, "_", 2)[0]
		ref := "deno:npm:" + common.ID(key)
		items["npm:"+key] = item{ref: ref, name: name, version: version, deps: meta.Dependencies, kind: "npm"}
		byName["npm:"+name] = append(byName["npm:"+name], "npm:"+key)
	}
	resolve := func(spec string) string {
		if strings.HasPrefix(spec, "http://") || strings.HasPrefix(spec, "https://") {
			if _, exists := lock.Remote[spec]; exists && safeurl.Clean(spec) != "" {
				return "remote:" + spec
			}
			return ""
		}
		kind := "npm"
		value := spec
		if strings.HasPrefix(value, "jsr:") {
			kind = "jsr"
			value = strings.TrimPrefix(value, "jsr:")
		} else {
			value = strings.TrimPrefix(value, "npm:")
		}
		name, version, withVersion := splitNameVersion(value)
		if !withVersion {
			name = value
		}
		if pinned, ok := lock.Specifiers[spec]; ok {
			version = pinned
			withVersion = true
		}
		if withVersion {
			key := kind + ":" + name + "@" + version
			if _, ok := items[key]; ok {
				return key
			}
			var matching string
			for _, candidate := range byName[kind+":"+name] {
				if strings.HasPrefix(candidate, key+"_") {
					if matching != "" {
						return ""
					}
					matching = candidate
				}
			}
			if matching != "" {
				return matching
			}
		}
		if matches := byName[kind+":"+name]; len(matches) == 1 {
			return matches[0]
		}
		return ""
	}
	visited := map[string]bool{}
	seenEdges := map[string]bool{}
	var visit func(key, from string)
	visit = func(key, from string) {
		if from != "" {
			to := key
			if value, ok := items[key]; ok {
				to = value.ref
			} else if strings.HasPrefix(key, "remote:") {
				to = "deno:remote:" + common.ID(key)
			}
			ekey := from + "\x00" + to
			if !seenEdges[ekey] {
				seenEdges[ekey] = true
				doc.Edges = append(doc.Edges, model.Edge{From: from, To: to, Kind: "depends_on", Evidence: common.Evidence(file, "deno-lock", "/specifiers", data)})
			}
		}
		if visited[key] {
			return
		}
		visited[key] = true
		if strings.HasPrefix(key, "remote:") {
			rawURL := strings.TrimPrefix(key, "remote:")
			clean := safeurl.Clean(rawURL)
			if clean == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source"})
				return
			}
			ref := "deno:remote:" + common.ID(key)
			ev := common.Evidence(file, "deno-lock", "/remote", data)
			doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "module", Name: clean, Hashes: common.HexSHA256(lock.Remote[rawURL]), Evidence: []model.Evidence{ev}})
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "download_url", SafeURL: clean, Status: "declared", Evidence: ev})
			return
		}
		entry := items[key]
		meta := packageEntry{}
		if entry.kind == "jsr" {
			meta = lock.JSR[strings.TrimPrefix(key, "jsr:")]
		} else {
			meta = lock.NPM[strings.TrimPrefix(key, "npm:")]
		}
		ev := common.Evidence(file, "deno-lock", "/"+entry.kind, data)
		component := model.Component{ID: entry.ref, Kind: "package", Name: entry.name, Version: entry.version, Evidence: []model.Evidence{ev}}
		if entry.kind == "jsr" {
			component.Hashes = common.HexSHA256(meta.Integrity)
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: entry.ref, Kind: "registry_identity", SafeURL: "https://jsr.io", Status: "inferred", Evidence: ev})
		} else {
			component.Hashes = common.Integrity(meta.Integrity)
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "source_unresolved", Name: entry.name})
		}
		doc.Components = append(doc.Components, component)
		for _, dep := range entry.deps {
			resolved := resolve(dep)
			if resolved == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: entry.name})
				continue
			}
			visit(resolved, entry.ref)
		}
	}
	for _, spec := range roots {
		key := resolve(spec)
		if key == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency"})
			continue
		}
		visit(key, "root")
	}
	// Static config alone does not capture every direct source import. The lock
	// can also retain stale entries, so no complete reachability claim is made.
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unreachable_graph"})
	common.Finalize(&doc)
	return doc, nil
}

func splitNameVersion(s string) (name, version string, ok bool) {
	idx := strings.Index(s, "@")
	if strings.HasPrefix(s, "@") {
		second := strings.Index(s[1:], "@")
		if second < 0 {
			return "", "", false
		}
		idx = second + 1
	}
	if idx <= 0 || idx == len(s)-1 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}
