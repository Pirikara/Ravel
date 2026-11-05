package gradle

import (
	"fmt"
	"os"
	"sort"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

// Collect reads Gradle's single-file dependency lock format. It contains a
// selected module inventory per configuration, not dependency relationships.
func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	doc := common.NewDocument(file, project, "gradle", data)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "transitive_graph_unavailable"}, model.Issue{Code: "missing_direct_dependencies"})
	seen := map[string]bool{}
	sawEntry := false
	for index, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rawConfigs, ok := strings.Cut(line, "=")
		if !ok {
			return model.Document{}, fmt.Errorf("invalid Gradle lockfile line %d", index+1)
		}
		sawEntry = true
		configs := []string{}
		if strings.TrimSpace(rawConfigs) != "" {
			for _, rawConfig := range strings.Split(rawConfigs, ",") {
				config := strings.TrimSpace(rawConfig)
				if config == "" || strings.ContainsAny(config, "\t =") {
					return model.Document{}, fmt.Errorf("invalid Gradle configuration at line %d", index+1)
				}
				configs = append(configs, config)
			}
		}
		if key == "empty" {
			continue
		}
		if len(configs) == 0 {
			return model.Document{}, fmt.Errorf("Gradle module at line %d has no configurations", index+1)
		}
		parts := strings.Split(key, ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" || strings.ContainsAny(key, " \t") {
			return model.Document{}, fmt.Errorf("invalid Gradle module at line %d", index+1)
		}
		if seen[key] {
			return model.Document{}, fmt.Errorf("duplicate Gradle module %q", key)
		}
		seen[key] = true
		sort.Strings(configs)
		configs = unique(configs)
		ref := "gradle:" + common.ID(key)
		ev := common.Evidence(file, "gradle-lock", fmt.Sprintf("/line/%d", index+1), data)
		ev.Line = index + 1
		doc.Components = append(doc.Components, model.Component{
			ID: ref, Kind: "package", Name: parts[0] + ":" + parts[1], Version: parts[2],
			Context: "configurations=" + strings.Join(configs, ","), Evidence: []model.Evidence{ev},
			PURL:      packageurl.NewPackageURL("maven", parts[0], parts[1], parts[2], nil, "").ToString(),
			PURLBasis: "ecosystem_inferred",
		})
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: parts[0] + ":" + parts[1]})
	}
	if !sawEntry {
		return model.Document{}, fmt.Errorf("Gradle lockfile has no lock entries")
	}
	common.Finalize(&doc)
	return doc, nil
}

func unique(sorted []string) []string {
	result := sorted[:0]
	for _, value := range sorted {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
