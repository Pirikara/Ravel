package nuget

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const MaxDepsJSONBytes = 16 << 20
const maxDepsLibraries = 10000

var depsLibraryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var depsVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9.+_-]*$`)
var depsTargetName = regexp.MustCompile(`^[A-Za-z0-9.,=_+()-]+(?:/[A-Za-z0-9._+-]+)?$`)

type depsManifest struct {
	RuntimeTarget struct {
		Name string `json:"name"`
	} `json:"runtimeTarget"`
	Targets   map[string]map[string]depsTargetLibrary `json:"targets"`
	Libraries map[string]depsLibrary                  `json:"libraries"`
}

type depsTargetLibrary struct {
	Dependencies   map[string]string `json:"dependencies"`
	Runtime        json.RawMessage   `json:"runtime"`
	Resources      json.RawMessage   `json:"resources"`
	Native         json.RawMessage   `json:"native"`
	RuntimeTargets json.RawMessage   `json:"runtimeTargets"`
}

type depsLibrary struct {
	Type   string `json:"type"`
	SHA512 string `json:"sha512"`
}

type depsEntry struct {
	name    string
	version string
	kind    string
	ref     string
	deps    map[string]string
}

// IsDepsManifestPath accepts the generated dependency manifest of an app or
// shared framework. The caller supplies a normalized image-relative path.
func IsDepsManifestPath(name string) bool {
	return name != "" && !strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "../") && path.Clean(name) == name && strings.HasSuffix(name, ".deps.json") && depsLibraryName.MatchString(strings.TrimSuffix(path.Base(name), ".deps.json"))
}

// CollectInstalledDeps reads the runtime target selected by a .NET dependency
// manifest. Its library list is evidence of the loader's intended graph, but
// is not proof that every referenced assembly is present in the image.
func CollectInstalledDeps(data []byte, source, project, manifestPath string) (model.Document, error) {
	if !IsDepsManifestPath(manifestPath) || len(data) == 0 || len(data) > MaxDepsJSONBytes {
		return model.Document{}, errors.New("invalid .NET deps manifest path or size")
	}
	var manifest depsManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return model.Document{}, fmt.Errorf("invalid .NET deps manifest: %w", err)
	}
	target := manifest.RuntimeTarget.Name
	if len(target) > 256 || !depsTargetName.MatchString(target) {
		return model.Document{}, errors.New("invalid .NET deps runtime target")
	}
	selected, ok := manifest.Targets[target]
	if !ok || selected == nil || manifest.Libraries == nil || len(selected) > maxDepsLibraries {
		return model.Document{}, errors.New("missing or oversized .NET deps runtime target or libraries")
	}
	hash := sha256.Sum256(data)
	evidence := model.Evidence{Collector: "nuget-deps", InputPath: source, InputDigest: "sha256:" + hex.EncodeToString(hash[:]), Method: "runtime-manifest"}
	doc := common.NewDocument(source, project, "nuget-deps", nil)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_runtime_assets_unverified", Name: manifestPath})
	keys := make([]string, 0, len(selected))
	for key := range selected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	keyByIdentity := map[string]string{}
	hasRuntimeAssets := map[string]bool{}
	for _, key := range keys {
		name, version, ok := strings.Cut(key, "/")
		if !ok || len(name) > 256 || len(version) > 128 || !depsLibraryName.MatchString(name) || !depsVersion.MatchString(version) {
			return model.Document{}, fmt.Errorf("invalid .NET deps library identity %q", key)
		}
		identity := strings.ToLower(name) + "/" + strings.ToLower(version)
		if _, duplicate := keyByIdentity[identity]; duplicate {
			return model.Document{}, fmt.Errorf("duplicate .NET deps library identity %q", key)
		}
		if _, found := manifest.Libraries[key]; !found {
			return model.Document{}, fmt.Errorf(".NET deps library metadata missing for %q", key)
		}
		keyByIdentity[identity] = key
		assets, err := hasDepsRuntimeAssets(selected[key])
		if err != nil {
			return model.Document{}, fmt.Errorf("invalid .NET deps runtime assets for %q: %w", key, err)
		}
		hasRuntimeAssets[key] = assets
	}
	parents := map[string][]string{}
	for _, key := range keys {
		for depName, depVersion := range selected[key].Dependencies {
			child := keyByIdentity[strings.ToLower(depName)+"/"+strings.ToLower(depVersion)]
			if child != "" {
				parents[child] = append(parents[child], key)
			}
		}
	}
	active := map[string]bool{}
	queue := []string{}
	rootName := strings.TrimSuffix(path.Base(manifestPath), ".deps.json")
	for _, key := range keys {
		name, _, _ := strings.Cut(key, "/")
		if hasRuntimeAssets[key] || manifest.Libraries[key].Type == "project" && strings.EqualFold(name, rootName) {
			active[key] = true
			queue = append(queue, key)
		}
	}
	for len(queue) > 0 {
		child := queue[0]
		queue = queue[1:]
		for _, parent := range parents[child] {
			if !active[parent] {
				active[parent] = true
				queue = append(queue, parent)
			}
		}
	}
	entries := map[string]depsEntry{}
	byIdentity := map[string]string{}
	projects := []depsEntry{}
	for _, key := range keys {
		name, version, _ := strings.Cut(key, "/")
		identity := strings.ToLower(name) + "/" + strings.ToLower(version)
		if !active[key] {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_non_runtime_library_omitted", Name: name})
			continue
		}
		library := manifest.Libraries[key]
		kind := "package"
		switch library.Type {
		case "package", "runtimepack":
		case "project":
			kind = "application"
		default:
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_library_type_unhandled", Name: name})
			continue
		}
		ref := "nuget-deps:" + common.ID(manifestPath+"\x00"+identity)
		entry := depsEntry{name: name, version: version, kind: kind, ref: ref, deps: selected[key].Dependencies}
		entries[key] = entry
		byIdentity[identity] = ref
		itemEvidence := evidence
		itemEvidence.Pointer = "/targets/" + escapePointer(target) + "/" + escapePointer(key)
		component := model.Component{ID: ref, Kind: kind, Name: name, Version: version, Platform: target, Context: "manifest=" + manifestPath, Evidence: []model.Evidence{itemEvidence}}
		if kind == "package" {
			if library.SHA512 != "" {
				component.Hashes = common.Integrity(library.SHA512)
				if len(component.Hashes) == 0 {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_package_hash_invalid", Name: name})
				}
			}
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "distribution_source_unavailable", Name: name})
			if !hasRuntimeAssets[key] {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_manifest_only_library", Name: name})
			}
			if library.Type == "runtimepack" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_runtimepack_identity_unverified", Name: name})
			}
		} else {
			projects = append(projects, entry)
		}
		doc.Components = append(doc.Components, component)
	}
	for _, key := range keys {
		entry, found := entries[key]
		if !found {
			continue
		}
		depNames := make([]string, 0, len(entry.deps))
		for depName := range entry.deps {
			depNames = append(depNames, depName)
		}
		sort.Strings(depNames)
		for _, depName := range depNames {
			depVersion := entry.deps[depName]
			if len(depName) > 256 || len(depVersion) > 128 || !depsLibraryName.MatchString(depName) || !depsVersion.MatchString(depVersion) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_dependency_invalid", Scope: entry.name})
				continue
			}
			to := byIdentity[strings.ToLower(depName)+"/"+strings.ToLower(depVersion)]
			if to == "" {
				if child := keyByIdentity[strings.ToLower(depName)+"/"+strings.ToLower(depVersion)]; child != "" && !active[child] {
					continue // This dependency has no path to a runtime asset.
				}
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: depName, Scope: entry.name})
				continue
			}
			if to == entry.ref {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_dependency_invalid", Name: depName, Scope: entry.name})
				continue
			}
			depEvidence := evidence
			depEvidence.Pointer = "/targets/" + escapePointer(target) + "/" + escapePointer(key) + "/dependencies/" + escapePointer(depName)
			doc.Edges = append(doc.Edges, model.Edge{From: entry.ref, To: to, Kind: "depends_on", Evidence: depEvidence})
		}
	}
	baseName := strings.TrimSuffix(path.Base(manifestPath), ".deps.json")
	if len(projects) == 0 {
		for _, component := range doc.Components {
			rootEvidence := component.Evidence[0]
			doc.Edges = append(doc.Edges, model.Edge{From: "root", To: component.ID, Kind: "installed", Evidence: rootEvidence})
		}
	} else {
		roots := []depsEntry{}
		for _, entry := range projects {
			if strings.EqualFold(entry.name, baseName) {
				roots = append(roots, entry)
			}
		}
		if len(roots) != 1 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_root_project_unresolved", Name: baseName})
		} else {
			root := roots[0]
			rootEvidence := evidence
			rootEvidence.Pointer = "/targets/" + escapePointer(target) + "/" + escapePointer(root.name+"/"+root.version)
			doc.Edges = append(doc.Edges, model.Edge{From: "root", To: root.ref, Kind: "installed", Evidence: rootEvidence})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func hasDepsRuntimeAssets(entry depsTargetLibrary) (bool, error) {
	hasAsset := false
	for _, raw := range []json.RawMessage{entry.Runtime, entry.Resources, entry.Native, entry.RuntimeTargets} {
		if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		var assets map[string]json.RawMessage
		if err := json.Unmarshal(raw, &assets); err != nil || assets == nil {
			return false, errors.New("runtime assets must be a JSON object")
		}
		for name := range assets {
			if path.Base(name) != "_._" {
				hasAsset = true
			}
		}
	}
	return hasAsset, nil
}
