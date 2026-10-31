package nuget

import (
	"encoding/json"
	"path"
	"sort"
	"strings"
)

// RuntimeAssemblyCandidates maps each library in the active target to the
// conventional flat publish path of its managed runtime assets. A deps entry
// names an intended asset, not an assembly identity or package-file checksum.
// The caller must first validate the manifest with CollectInstalledDeps.
func RuntimeAssemblyCandidates(data []byte, manifestPath string) map[string][]string {
	result := map[string][]string{}
	if !IsDepsManifestPath(manifestPath) || len(data) > MaxDepsJSONBytes {
		return result
	}
	var manifest depsManifest
	if json.Unmarshal(data, &manifest) != nil {
		return result
	}
	selected := manifest.Targets[manifest.RuntimeTarget.Name]
	for identity, entry := range selected {
		if len(entry.Runtime) == 0 {
			continue
		}
		var runtimeAssets map[string]json.RawMessage
		if json.Unmarshal(entry.Runtime, &runtimeAssets) != nil {
			continue
		}
		seen := map[string]bool{}
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
				result[strings.ToLower(identity)] = append(result[strings.ToLower(identity)], file)
			}
		}
		sort.Strings(result[strings.ToLower(identity)])
	}
	return result
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
	return true
}
