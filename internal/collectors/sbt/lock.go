package sbt

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

	packageurl "github.com/package-url/packageurl-go"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const maxLockBytes = 16 << 20

var coordinate = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,256}$`)
var sha1Hash = regexp.MustCompile(`^sha1:([0-9a-fA-F]{40})$`)

type lockfile struct {
	LockVersion    int               `json:"lockVersion"`
	Configurations []string          `json:"configurations"`
	Dependencies   []json.RawMessage `json:"dependencies"`
}

type dependency struct {
	Org            string   `json:"org"`
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Configurations []string `json:"configurations"`
	Artifacts      []struct {
		Name string `json:"name"`
		Hash string `json:"hash"`
	} `json:"artifacts"`
}

func CollectLock(filename, project string) (model.Document, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxLockBytes {
		return model.Document{}, errors.New("sbt lockfile size is invalid or exceeds limit")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return model.Document{}, err
	}
	if len(data) > maxLockBytes {
		return model.Document{}, errors.New("sbt lockfile exceeds size limit")
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid sbt lockfile JSON: %w", err)
	}
	if lock.LockVersion != 1 {
		return model.Document{}, fmt.Errorf("unsupported sbt lockfile version %d", lock.LockVersion)
	}
	if lock.Dependencies == nil {
		return model.Document{}, errors.New("sbt lockfile has no dependencies array")
	}
	doc := common.NewDocument(filename, project, "sbt", data)
	for index, raw := range lock.Dependencies {
		var dep dependency
		if err := json.Unmarshal(raw, &dep); err != nil || !coordinate.MatchString(dep.Org) || !coordinate.MatchString(dep.Name) || !validVersion(dep.Version) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "sbt_dependency_invalid", Name: fmt.Sprint(index)})
			continue
		}
		configs := make([]string, 0, len(dep.Configurations))
		validConfigs := true
		for _, config := range dep.Configurations {
			if !coordinate.MatchString(config) {
				validConfigs = false
				break
			}
			configs = append(configs, config)
		}
		if !validConfigs {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "sbt_configuration_invalid", Name: dep.Org + ":" + dep.Name})
			continue
		}
		sort.Strings(configs)
		configs = unique(configs)
		id := "sbt:" + common.ID(filename+"\x00"+dep.Org+"\x00"+dep.Name+"\x00"+dep.Version+"\x00"+strings.Join(configs, ",")+"\x00"+fmt.Sprint(index))
		evidence := common.Evidence(filename, "sbt-lock", fmt.Sprintf("/dependencies/%d", index), data)
		component := model.Component{ID: id, Kind: "package", Name: dep.Org + ":" + dep.Name, Version: dep.Version, PURL: packageurl.NewPackageURL("maven", dep.Org, dep.Name, dep.Version, nil, "").ToString(), Evidence: []model.Evidence{evidence}}
		if len(configs) > 0 {
			component.Context = "configurations=" + strings.Join(configs, ",")
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "sbt_configuration_unavailable", Name: component.Name})
		}
		if len(dep.Artifacts) == 1 && dep.Artifacts[0].Name == dep.Name+".jar" {
			if match := sha1Hash.FindStringSubmatch(dep.Artifacts[0].Hash); match != nil {
				component.Hashes = []model.Hash{{Alg: "SHA-1", Content: strings.ToLower(match[1])}}
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "sbt_artifact_hash_unverified", Name: component.Name})
			}
		} else if len(dep.Artifacts) > 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "sbt_artifact_hash_unverified", Name: component.Name})
		}
		doc.Components = append(doc.Components, component)
		if len(doc.Components) > 100000 {
			return model.Document{}, errors.New("sbt lockfile has too many dependencies")
		}
	}
	if len(doc.Components) == 0 && len(lock.Dependencies) > 0 {
		return model.Document{}, errors.New("sbt lockfile has no valid dependencies")
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "sbt_dependency_graph_unavailable"},
		model.Issue{Code: "sbt_distribution_origin_unverified"},
		model.Issue{Code: "manifest_freshness_unverified"})
	common.Finalize(&doc)
	return doc, nil
}

func validVersion(version string) bool {
	return version != "" && len(version) <= 128 && strings.IndexFunc(version, unicode.IsControl) < 0
}

func unique(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
