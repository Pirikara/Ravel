package deno

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

type lockfile struct {
	Version    string                  `json:"version"`
	Packages   json.RawMessage         `json:"packages"`
	Specifiers map[string]string       `json:"specifiers"`
	JSR        map[string]packageEntry `json:"jsr"`
	NPM        map[string]packageEntry `json:"npm"`
	Remote     map[string]string       `json:"remote"`
	Workspace  struct {
		Dependencies []string `json:"dependencies"`
	} `json:"workspace"`
}

type v3Packages struct {
	Specifiers map[string]string         `json:"specifiers"`
	JSR        map[string]v3PackageEntry `json:"jsr"`
	NPM        map[string]v3PackageEntry `json:"npm"`
}

type v3PackageEntry struct {
	Integrity    string            `json:"integrity"`
	Dependencies map[string]string `json:"dependencies"`
}

type packageEntry struct {
	Integrity    string   `json:"integrity"`
	Dependencies []string `json:"dependencies"`
}

type configFile struct {
	Imports   map[string]string            `json:"imports"`
	Scopes    map[string]map[string]string `json:"scopes"`
	ImportMap string                       `json:"importMap"`
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

// Collect emits the package closure observed in config, workspace dependencies,
// and project source imports. Runtime-selected entry points and nonliteral
// dynamic imports remain unknown, so the static result explicitly stays partial.
func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid deno.lock: %w", err)
	}
	if lock.Version == "3" {
		if err := normalizeV3(&lock); err != nil {
			return model.Document{}, err
		}
	} else if lock.Version != "4" && lock.Version != "5" {
		return model.Document{}, fmt.Errorf("unsupported deno.lock version %q", lock.Version)
	}
	doc := common.NewDocument(file, project, "deno", data)
	base := filepath.Dir(file)
	var roots []string
	var config configFile
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
		if err := json.Unmarshal(standard, &config); err != nil {
			return model.Document{}, fmt.Errorf("invalid %s: %w", name, err)
		}
		break
	}
	if config.ImportMap != "" {
		importMap, path, err := readImportMap(base, config.ImportMap)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "source_import_map_unavailable"})
		} else {
			config.Imports, config.Scopes = importMap.Imports, importMap.Scopes
			doc.Sources = append(doc.Sources, path)
		}
	}
	for _, value := range config.Imports {
		if !strings.HasPrefix(value, "./") && !strings.HasPrefix(value, "../") {
			roots = append(roots, value)
		}
	}
	packageDeps := map[string]string{}
	if packageData, err := os.ReadFile(filepath.Join(base, "package.json")); err == nil {
		doc.Sources = append(doc.Sources, filepath.Join(base, "package.json"))
		var pkg packageJSON
		if json.Unmarshal(packageData, &pkg) == nil {
			for name, constraint := range pkg.Dependencies {
				packageDeps[name] = constraint
				roots = append(roots, "npm:"+name+"@"+constraint)
			}
			for name, constraint := range pkg.DevDependencies {
				packageDeps[name] = constraint
				roots = append(roots, "npm:"+name+"@"+constraint)
			}
		}
	}
	roots = append(roots, lock.Workspace.Dependencies...)
	sourceImports, sourceFiles, sourceIssues := scanSourceImports(base)
	doc.Sources = append(doc.Sources, sourceFiles...)
	doc.Coverage.Issues = append(doc.Coverage.Issues, sourceIssues...)
	if len(roots) == 0 && len(sourceFiles) == 0 {
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
			name = barePackageName(value)
		}
		if pinned, ok := lock.Specifiers[spec]; ok {
			version = pinned
			withVersion = true
		} else if withVersion {
			if slash := strings.IndexByte(version, '/'); slash >= 0 {
				version = version[:slash]
				if pinned, ok := lock.Specifiers[kind+":"+name+"@"+version]; ok {
					version = pinned
				}
			}
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
			return ""
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
	scanned := make(map[string]bool, len(sourceFiles))
	for _, source := range sourceFiles {
		scanned[filepath.Clean(source)] = true
	}
	for _, observed := range sourceImports {
		spec, fromMap := mappedSourceSpecifier(observed.specifier, observed.path, base, config.Imports, config.Scopes)
		if !fromMap {
			spec = observed.specifier
		}
		if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") {
			target, ok := localSourcePath(spec, observed.path, base, fromMap)
			if !ok {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "local source import", Scope: observed.path})
			} else if _, source := sourceLoader(filepath.Ext(target)); source && !scanned[filepath.Clean(target)] {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "source_scan_limited", Scope: target})
			}
			continue
		}
		if strings.HasPrefix(spec, "node:") || strings.HasPrefix(spec, "data:") {
			continue
		}
		if !fromMap && !strings.Contains(spec, ":") {
			name := barePackageName(spec)
			constraint, ok := packageDeps[name]
			if !ok {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "bare source import", Scope: observed.path})
				continue
			}
			spec = "npm:" + name + "@" + constraint
		}
		if !strings.HasPrefix(spec, "jsr:") && !strings.HasPrefix(spec, "npm:") &&
			!strings.HasPrefix(spec, "https://") && !strings.HasPrefix(spec, "http://") {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "source import", Scope: observed.path})
			continue
		}
		key := resolve(spec)
		if key == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "source import absent from lockfile", Scope: observed.path})
			continue
		}
		ref := ""
		if entry, ok := items[key]; ok {
			ref = entry.ref
		} else if strings.HasPrefix(key, "remote:") {
			ref = "deno:remote:" + common.ID(key)
		}
		if ref == "" {
			continue
		}
		visit(key, "")
		edgeKey := "root\x00" + ref
		if !seenEdges[edgeKey] {
			seenEdges[edgeKey] = true
			doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ref, Kind: "depends_on", Evidence: observed.evidence})
		}
		for i := range doc.Components {
			if doc.Components[i].ID != ref {
				continue
			}
			found := false
			for _, evidence := range doc.Components[i].Evidence {
				if evidence.InputPath == observed.evidence.InputPath && evidence.Method == observed.evidence.Method {
					found = true
					break
				}
			}
			if !found {
				doc.Components[i].Evidence = append(doc.Components[i].Evidence, observed.evidence)
			}
			break
		}
	}
	// An arbitrary runtime entry point or computed import can still be absent.
	// The lock can also retain stale entries, so no complete reachability claim is made.
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unreachable_graph"})
	common.Finalize(&doc)
	return doc, nil
}

// Version 3 nests package records and records pinned specifiers with their
// ecosystem prefix. Normalize that shape so graph traversal is shared with
// the version 4/5 collector.
func normalizeV3(lock *lockfile) error {
	if len(lock.Packages) == 0 {
		return fmt.Errorf("deno.lock v3 has no packages object")
	}
	var packages v3Packages
	if err := json.Unmarshal(lock.Packages, &packages); err != nil {
		return fmt.Errorf("invalid deno.lock v3 packages: %w", err)
	}
	lock.Specifiers = make(map[string]string, len(packages.Specifiers))
	for spec, pin := range packages.Specifiers {
		kind, value, ok := strings.Cut(pin, ":")
		if !ok || kind != "npm" && kind != "jsr" {
			return fmt.Errorf("unsupported deno.lock v3 pin %q", pin)
		}
		name, version, ok := splitNameVersion(value)
		if !ok || name == "" {
			return fmt.Errorf("invalid deno.lock v3 pin %q", pin)
		}
		lock.Specifiers[spec] = version
	}
	lock.JSR = normalizeV3Entries(packages.JSR)
	lock.NPM = normalizeV3Entries(packages.NPM)
	return nil
}

func normalizeV3Entries(entries map[string]v3PackageEntry) map[string]packageEntry {
	out := make(map[string]packageEntry, len(entries))
	for key, entry := range entries {
		deps := make([]string, 0, len(entry.Dependencies))
		for _, value := range entry.Dependencies {
			deps = append(deps, value)
		}
		sort.Strings(deps)
		out[key] = packageEntry{Integrity: entry.Integrity, Dependencies: deps}
	}
	return out
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
