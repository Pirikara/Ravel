package condalock

import (
	"errors"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

	packageurl "github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

const maxLockBytes = 32 << 20

var packageName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,255}$`)
var platformName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var sha256Digest = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
var md5Digest = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
var pythonNameSeparators = regexp.MustCompile(`[-_.]+`)

type lockfile struct {
	Version  int `yaml:"version"`
	Metadata struct {
		Platforms []string `yaml:"platforms"`
	} `yaml:"metadata"`
	Packages []packageRecord `yaml:"package"`
}

type packageRecord struct {
	Name         string            `yaml:"name"`
	Version      string            `yaml:"version"`
	Manager      string            `yaml:"manager"`
	Platform     string            `yaml:"platform"`
	Dependencies map[string]string `yaml:"dependencies"`
	URL          string            `yaml:"url"`
	Hash         struct {
		MD5    string `yaml:"md5"`
		SHA256 string `yaml:"sha256"`
	} `yaml:"hash"`
	Category string `yaml:"category"`
	Optional bool   `yaml:"optional"`
}

type occurrence struct {
	record   packageRecord
	id       string
	evidence model.Evidence
}

func CollectLock(filename, project string) (model.Document, error) {
	file, err := os.Open(filename)
	if err != nil {
		return model.Document{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxLockBytes {
		return model.Document{}, errors.New("conda-lock file size is invalid or exceeds limit")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return model.Document{}, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return model.Document{}, fmt.Errorf("invalid conda-lock YAML: %w", err)
	}
	if err := checkYAML(&root, 0, new(int)); err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := root.Decode(&lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid conda-lock content: %w", err)
	}
	if lock.Version != 1 || lock.Packages == nil {
		return model.Document{}, errors.New("unsupported or empty conda-lock v1 file")
	}
	doc := common.NewDocument(filename, project, "conda-lock", data)
	platforms := map[string]bool{}
	for _, platform := range lock.Metadata.Platforms {
		if platformName.MatchString(platform) {
			platforms[platform] = true
		}
	}
	for platform := range platforms {
		doc.Coverage.Platforms = append(doc.Coverage.Platforms, platform)
	}
	sort.Strings(doc.Coverage.Platforms)
	byPlatform := map[string]map[string][]occurrence{}
	var records []occurrence
	for index, pkg := range lock.Packages {
		if !packageName.MatchString(pkg.Name) || !validVersion(pkg.Version) || !platformName.MatchString(pkg.Platform) || pkg.Manager != "conda" && pkg.Manager != "pip" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conda_lock_package_invalid", Name: fmt.Sprint(index)})
			continue
		}
		if len(platforms) > 0 && !platforms[pkg.Platform] {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conda_lock_platform_unlisted", Name: pkg.Name, Scope: pkg.Platform})
		}
		id := "conda-lock:" + common.ID(filename+"\x00"+fmt.Sprint(index)+"\x00"+pkg.Manager+"\x00"+pkg.Platform+"\x00"+pkg.Name)
		evidence := common.Evidence(filename, "conda-lock", fmt.Sprintf("/package/%d", index), data)
		context := "manager=" + pkg.Manager
		if pkg.Category != "" {
			if platformName.MatchString(pkg.Category) {
				context += ";category=" + pkg.Category
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conda_lock_category_invalid", Name: pkg.Name, Scope: pkg.Platform})
			}
		}
		if pkg.Optional {
			context += ";optional=true"
		}
		component := model.Component{ID: id, Kind: "package", Name: pkg.Name, Version: pkg.Version, Platform: pkg.Platform, Context: context, Evidence: []model.Evidence{evidence}}
		if pkg.Manager == "pip" {
			if parsed, err := neturl.Parse(pkg.URL); err == nil && (parsed.Hostname() == "files.pythonhosted.org" || parsed.Hostname() == "pypi.org") {
				component.PURL = packageurl.NewPackageURL("pypi", "", pythonNameSeparators.ReplaceAllString(strings.ToLower(pkg.Name), "-"), pkg.Version, nil, "").ToString()
			}
		}
		if sha256Digest.MatchString(pkg.Hash.SHA256) {
			component.Hashes = append(component.Hashes, model.Hash{Alg: "SHA-256", Content: strings.ToLower(pkg.Hash.SHA256)})
		} else if pkg.Hash.SHA256 != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conda_lock_hash_invalid", Name: pkg.Name, Scope: pkg.Platform})
		}
		if md5Digest.MatchString(pkg.Hash.MD5) {
			component.Hashes = append(component.Hashes, model.Hash{Alg: "MD5", Content: strings.ToLower(pkg.Hash.MD5)})
		} else if pkg.Hash.MD5 != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conda_lock_hash_invalid", Name: pkg.Name, Scope: pkg.Platform})
		}
		if pkg.URL != "" && !strings.ContainsAny(pkg.URL, "${}") {
			if clean := safeurl.Clean(pkg.URL); clean != "" {
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "download_url", SafeURL: clean, Status: "declared", Evidence: evidence})
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: pkg.Name, Scope: pkg.Platform})
			}
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conda_lock_source_unresolved", Name: pkg.Name, Scope: pkg.Platform})
		}
		doc.Components = append(doc.Components, component)
		occ := occurrence{record: pkg, id: id, evidence: evidence}
		records = append(records, occ)
		if byPlatform[pkg.Platform] == nil {
			byPlatform[pkg.Platform] = map[string][]occurrence{}
		}
		byPlatform[pkg.Platform][pkg.Name] = append(byPlatform[pkg.Platform][pkg.Name], occ)
		if len(records) > 100000 {
			return model.Document{}, errors.New("conda-lock has too many packages")
		}
	}
	if len(records) == 0 && len(lock.Packages) > 0 {
		return model.Document{}, errors.New("conda-lock has no valid package entries")
	}
	for _, parent := range records {
		for name := range parent.record.Dependencies {
			if !packageName.MatchString(name) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conda_lock_dependency_invalid", Name: parent.record.Name})
				continue
			}
			if strings.HasPrefix(name, "__") {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conda_virtual_requirement_unresolved", Name: name, Scope: parent.record.Platform})
				continue
			}
			matches := byPlatform[parent.record.Platform][name]
			if len(matches) == 0 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name, Scope: parent.record.Platform})
				continue
			}
			if len(matches) != 1 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: name, Scope: parent.record.Platform})
				continue
			}
			evidence := parent.evidence
			evidence.Pointer += "/dependencies/" + name
			doc.Edges = append(doc.Edges, model.Edge{From: parent.id, To: matches[0].id, Kind: "requires", Condition: "version constraint unverified", Evidence: evidence})
		}
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "missing_direct_dependencies"},
		model.Issue{Code: "conda_lock_constraints_unverified"},
		model.Issue{Code: "conda_lock_distribution_bytes_unverified"})
	common.Finalize(&doc)
	return doc, nil
}

func validVersion(version string) bool {
	return version != "" && len(version) <= 128 && strings.IndexFunc(version, unicode.IsControl) < 0
}

func checkYAML(node *yaml.Node, depth int, count *int) error {
	*count = *count + 1
	if depth > 64 || *count > 250000 {
		return errors.New("conda-lock YAML exceeds nesting or node limit")
	}
	if node.Kind == yaml.AliasNode {
		return errors.New("conda-lock YAML aliases are unsupported")
	}
	for _, child := range node.Content {
		if err := checkYAML(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}
