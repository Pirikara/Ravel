package pixi

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const maxManifestBytes = 4 << 20

type directRequest struct {
	name, manager, pointer string
}

func addManifest(doc *model.Document, lockPath string, lock lockfile, byScope map[string]map[string][]occurrence) error {
	manifestPath := filepath.Join(filepath.Dir(lockPath), "pixi.toml")
	file, err := os.Open(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return errors.New("pixi.toml size is invalid or exceeds limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxManifestBytes {
		return errors.New("pixi.toml exceeds size limit")
	}
	var manifest map[string]any
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("invalid pixi.toml: %w", err)
	}
	doc.Sources = append(doc.Sources, manifestPath)
	features := asTable(manifest["feature"])
	environments := asTable(manifest["environments"])
	names := make([]string, 0, len(lock.Environments))
	for name := range lock.Environments {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, envName := range names {
		envValue, declared := environments[envName]
		if !declared && envName != "default" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_environment_unresolved", Name: envName})
			continue
		}
		envTable, featureNames, includeDefault, valid := environmentConfig(envValue, declared)
		if !valid {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_environment_unresolved", Name: envName})
			continue
		}
		platforms := make([]string, 0, len(lock.Environments[envName].Packages))
		for platform := range lock.Environments[envName].Packages {
			platforms = append(platforms, platform)
		}
		sort.Strings(platforms)
		for _, platform := range platforms {
			var requests []directRequest
			if includeDefault {
				requests = appendRequests(doc, requests, manifest, "", platform)
				if defaultFeature := asTable(features["default"]); defaultFeature != nil {
					requests = appendRequests(doc, requests, defaultFeature, "/feature/default", platform)
				}
			}
			for _, featureName := range featureNames {
				if featureName == "default" && includeDefault {
					continue
				}
				feature := asTable(features[featureName])
				if feature == nil {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_feature_unresolved", Name: featureName, Scope: envName})
					continue
				}
				if !featureApplies(doc, feature, featureName, platform) {
					continue
				}
				requests = appendRequests(doc, requests, feature, "/feature/"+featureName, platform)
			}
			if envTable != nil {
				requests = appendRequests(doc, requests, envTable, "/environments/"+envName, platform)
			}
			appendRootEdges(doc, requests, byScope[envName+"\x00"+platform], envName, platform, manifestPath, data)
		}
	}
	return nil
}

func environmentConfig(value any, declared bool) (map[string]any, []string, bool, bool) {
	if !declared {
		return nil, nil, true, true
	}
	if list, ok := value.([]any); ok {
		names, valid := stringList(list)
		return nil, names, true, valid
	}
	table := asTable(value)
	if table == nil {
		return nil, nil, false, false
	}
	includeDefault := true
	if raw, found := table["no-default-feature"]; found {
		value, ok := raw.(bool)
		if !ok {
			return nil, nil, false, false
		}
		includeDefault = !value
	}
	var features []string
	if raw, found := table["features"]; found {
		list, ok := raw.([]any)
		if !ok {
			return nil, nil, false, false
		}
		var valid bool
		features, valid = stringList(list)
		if !valid {
			return nil, nil, false, false
		}
	}
	return table, features, includeDefault, true
}

func appendRequests(doc *model.Document, requests []directRequest, scope map[string]any, pointer, platform string) []directRequest {
	requests = appendTableRequests(doc, requests, scope, pointer)
	targets := asTable(scope["target"])
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, selector := range names {
		if targetMatches(selector, platform) {
			if target := asTable(targets[selector]); target != nil {
				requests = appendTableRequests(doc, requests, target, pointer+"/target/"+selector)
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_target_unresolved", Name: selector})
			}
		}
	}
	return requests
}

func appendTableRequests(doc *model.Document, requests []directRequest, scope map[string]any, pointer string) []directRequest {
	if scope["dev"] != nil || scope["host-dependencies"] != nil || scope["build-dependencies"] != nil {
		name := pointer
		if name == "" {
			name = "/"
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_dependency_category_unhandled", Name: name})
	}
	for _, kind := range []struct{ table, manager string }{{"dependencies", "conda"}, {"pypi-dependencies", "pypi"}} {
		raw, found := scope[kind.table]
		if !found {
			continue
		}
		entries := asTable(raw)
		if entries == nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_dependency_table_unresolved", Name: kind.table})
			continue
		}
		names := make([]string, 0, len(entries))
		for name := range entries {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if !namePattern.MatchString(name) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_dependency_invalid"})
				continue
			}
			requests = append(requests, directRequest{name: name, manager: kind.manager, pointer: pointer + "/" + kind.table + "/" + name})
		}
	}
	return requests
}

func appendRootEdges(doc *model.Document, requests []directRequest, selected map[string][]occurrence, envName, platform, filename string, data []byte) {
	index := map[string][]occurrence{}
	for _, entries := range selected {
		for _, entry := range entries {
			name := entry.record.name
			if entry.record.manager == "pypi" {
				name = normalizePyPIName(name)
			}
			key := entry.record.manager + "\x00" + name
			index[key] = append(index[key], entry)
		}
	}
	seen := map[string]bool{}
	for _, request := range requests {
		name := request.name
		if request.manager == "pypi" {
			name = normalizePyPIName(name)
		}
		key := request.manager + "\x00" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		matches := index[key]
		if len(matches) != 1 {
			code := "unresolved_dependency"
			if len(matches) > 1 {
				code = "ambiguous_dependency"
			}
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: request.name, Scope: envName + "/" + platform})
			continue
		}
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: matches[0].id, Kind: "direct", Condition: "environment=" + envName + "; platform=" + platform + "; manifest constraint unverified", Evidence: common.Evidence(filename, "pixi-manifest", request.pointer, data)})
	}
}

func featureApplies(doc *model.Document, feature map[string]any, name, platform string) bool {
	raw, found := feature["platforms"]
	if !found {
		return true
	}
	list, ok := raw.([]any)
	if !ok {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_feature_platform_unresolved", Name: name})
		return false
	}
	platforms, valid := stringList(list)
	if !valid {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_feature_platform_unresolved", Name: name})
		return false
	}
	for _, selected := range platforms {
		if selected == platform {
			return true
		}
	}
	return false
}

func targetMatches(selector, platform string) bool {
	if selector == platform {
		return true
	}
	switch selector {
	case "linux", "osx", "win":
		return strings.HasPrefix(platform, selector+"-")
	case "unix":
		return strings.HasPrefix(platform, "linux-") || strings.HasPrefix(platform, "osx-")
	}
	return false
}

func stringList(raw []any) ([]string, bool) {
	result := make([]string, 0, len(raw))
	for _, value := range raw {
		name, ok := value.(string)
		if !ok || !scopePattern.MatchString(name) {
			return nil, false
		}
		result = append(result, name)
	}
	return result, true
}

func asTable(value any) map[string]any {
	table, _ := value.(map[string]any)
	return table
}
