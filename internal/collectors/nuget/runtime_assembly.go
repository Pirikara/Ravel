package nuget

import (
	"encoding/json"
	"path"
	"sort"
	"strings"
)

type RuntimeAssemblyCandidate struct {
	Path string
	RID  string // Empty for a platform-neutral runtime asset.
}

// RuntimeAssemblyCandidates maps each library in the active target to the
// conventional publish path of its managed runtime assets. RID-specific
// assets keep their relative runtimes/ path; the host's RID selection is not
// inferred. A deps entry is not an assembly identity or package-file checksum.
// The caller must first validate the manifest with CollectInstalledDeps.
func RuntimeAssemblyCandidates(data []byte, manifestPath string) map[string][]RuntimeAssemblyCandidate {
	result := map[string][]RuntimeAssemblyCandidate{}
	if !IsDepsManifestPath(manifestPath) || len(data) > MaxDepsJSONBytes {
		return result
	}
	var manifest depsManifest
	if json.Unmarshal(data, &manifest) != nil {
		return result
	}
	selected := manifest.Targets[manifest.RuntimeTarget.Name]
	for identity, entry := range selected {
		key := strings.ToLower(identity)
		seen := map[string]bool{}
		var runtimeAssets map[string]json.RawMessage
		if len(entry.Runtime) != 0 {
			_ = json.Unmarshal(entry.Runtime, &runtimeAssets)
		}
		for asset, description := range runtimeAssets {
			if !safeRuntimeDLLAsset(asset) {
				continue
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(description, &fields) != nil || fields == nil {
				continue
			}
			file := path.Join(path.Dir(manifestPath), path.Base(asset))
			if !seen[file] {
				seen[file] = true
				result[key] = append(result[key], RuntimeAssemblyCandidate{Path: file})
			}
		}
		var specific map[string]json.RawMessage
		if len(entry.RuntimeTargets) != 0 {
			_ = json.Unmarshal(entry.RuntimeTargets, &specific)
		}
		for asset, description := range specific {
			if !safeRuntimeDLLAsset(asset) {
				continue
			}
			var fields struct {
				RID       string `json:"rid"`
				AssetType string `json:"assetType"`
			}
			if json.Unmarshal(description, &fields) != nil || fields.AssetType != "runtime" || !safeRuntimeRID(fields.RID) || !strings.HasPrefix(asset, "runtimes/"+fields.RID+"/lib/") {
				continue
			}
			file := path.Join(path.Dir(manifestPath), asset)
			if !seen[file] {
				seen[file] = true
				result[key] = append(result[key], RuntimeAssemblyCandidate{Path: file, RID: fields.RID})
			}
		}
		sort.Slice(result[key], func(i, j int) bool { return result[key][i].Path < result[key][j].Path })
	}
	return result
}

func safeRuntimeRID(rid string) bool {
	if rid == "" || len(rid) > 128 || rid == "." || rid == ".." {
		return false
	}
	for _, character := range rid {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func safeRuntimeDLLAsset(asset string) bool {
	if asset == "" || len(asset) > 512 || strings.HasPrefix(asset, "/") || path.Clean(asset) != asset || strings.ContainsAny(asset, "\\:\x00") || !strings.HasSuffix(strings.ToLower(asset), ".dll") {
		return false
	}
	for _, segment := range strings.Split(asset, "/") {
		if segment == ".." || segment == "." || segment == "" {
			return false
		}
	}
	for _, character := range asset {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
