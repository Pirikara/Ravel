package composer

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

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const MaxInstalledJSONBytes = 16 << 20
const maxInstalledPackages = 5000

var installedPackageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)

type installedPackage struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	InstallPath string            `json:"install-path"`
	Require     map[string]string `json:"require"`
	Provide     map[string]string `json:"provide"`
	Replace     map[string]string `json:"replace"`
}

// IsInstalledManifestPath recognizes Composer's installed-package database
// below its vendor directory, including a configured vendor-dir.
func IsInstalledManifestPath(name string) bool {
	return name != "" && !strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "../") && path.Clean(name) == name && (name == "composer/installed.json" || strings.HasSuffix(name, "/composer/installed.json"))
}

// CollectInstalled inventories packages recorded in Composer 1 or 2
// installed.json. The file describes an installation; it does not prove the
// presence of every package file or the origin of its distribution.
func CollectInstalled(data []byte, source, project, metadataPath string) (model.Document, error) {
	if !IsInstalledManifestPath(metadataPath) || len(data) == 0 || len(data) > MaxInstalledJSONBytes {
		return model.Document{}, errors.New("invalid Composer installed metadata path or size")
	}
	packages, packagePath, err := parseInstalledPackages(data)
	if err != nil {
		return model.Document{}, err
	}
	hash := sha256.Sum256(data)
	evidence := model.Evidence{Collector: "composer-installed", InputPath: source, InputDigest: "sha256:" + hex.EncodeToString(hash[:]), Method: "installed-metadata"}
	doc := common.NewDocument(source, project, "composer-installed", nil)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_installed_files_unverified", Name: metadataPath})
	byName := map[string][]string{}
	byCapability := map[string][]string{}
	refs := make([]string, len(packages))
	seen := map[string]bool{}
	for i, pkg := range packages {
		if !validInstalledPackageName(pkg.Name) || !validInstalledVersion(pkg.Version) {
			return model.Document{}, fmt.Errorf("invalid Composer installed package identity at index %d", i)
		}
		name := strings.ToLower(pkg.Name)
		if seen[name] {
			return model.Document{}, fmt.Errorf("duplicate Composer installed package %s", pkg.Name)
		}
		seen[name] = true
		ref := "composer-installed:" + common.ID(metadataPath+"\x00"+name+"\x00"+pkg.Version)
		refs[i] = ref
		byName[name] = append(byName[name], ref)
		for capability := range pkg.Provide {
			if validInstalledPackageName(capability) {
				byCapability[strings.ToLower(capability)] = append(byCapability[strings.ToLower(capability)], ref)
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_installed_provider_invalid", Name: capability, Scope: pkg.Name})
			}
		}
		for capability := range pkg.Replace {
			if validInstalledPackageName(capability) {
				byCapability[strings.ToLower(capability)] = append(byCapability[strings.ToLower(capability)], ref)
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_installed_provider_invalid", Name: capability, Scope: pkg.Name})
			}
		}
		packageEvidence := evidence
		packageEvidence.Pointer = fmt.Sprintf("%s/%d", packagePath, i)
		doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: pkg.Name, Version: pkg.Version, Context: "registry=" + metadataPath, Evidence: []model.Evidence{packageEvidence}})
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ref, Kind: "installed", Evidence: packageEvidence})
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "distribution_source_unavailable", Name: pkg.Name})
	}
	for i, pkg := range packages {
		requirementNames := make([]string, 0, len(pkg.Require))
		for name := range pkg.Require {
			requirementNames = append(requirementNames, name)
		}
		sort.Strings(requirementNames)
		for _, name := range requirementNames {
			if isPlatform(name) {
				continue
			}
			if !validInstalledPackageName(name) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_installed_requirement_invalid", Name: name, Scope: pkg.Name})
				continue
			}
			constraint := strings.TrimSpace(pkg.Require[name])
			if constraint == "" || len(constraint) > 1024 || strings.ContainsAny(constraint, "\x00\r\n") {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_installed_requirement_invalid", Name: name, Scope: pkg.Name})
				continue
			}
			candidates := byName[strings.ToLower(name)]
			virtual := false
			if len(candidates) == 0 {
				candidates = byCapability[strings.ToLower(name)]
				virtual = len(candidates) > 0
			}
			if len(candidates) == 0 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name, Scope: pkg.Name})
				continue
			}
			condition := ""
			if constraint != "*" {
				condition = "composer_constraint=unverified"
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dependency_constraint_unverified", Name: name, Scope: pkg.Name})
			}
			if virtual {
				condition = appendInstalledCondition(condition, "provider=virtual")
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_installed_virtual_provider_unverified", Name: name, Scope: pkg.Name})
			}
			unique := map[string]bool{}
			for _, candidate := range candidates {
				unique[candidate] = true
			}
			if len(unique) > 1 {
				condition = appendInstalledCondition(condition, "provider=ambiguous")
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: name, Scope: pkg.Name})
			}
			targets := make([]string, 0, len(unique))
			for target := range unique {
				targets = append(targets, target)
			}
			sort.Strings(targets)
			for _, target := range targets {
				if target == refs[i] {
					continue // A package's own capability needs no dependency edge.
				}
				dependencyEvidence := evidence
				dependencyEvidence.Pointer = fmt.Sprintf("%s/%d/require/%s", packagePath, i, installedPointerToken(name))
				doc.Edges = append(doc.Edges, model.Edge{From: refs[i], To: target, Kind: "depends_on", Condition: condition, Evidence: dependencyEvidence})
			}
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func parseInstalledPackages(data []byte) ([]installedPackage, string, error) {
	raw := bytes.TrimSpace(data)
	if len(raw) == 0 {
		return nil, "", errors.New("empty Composer installed metadata")
	}
	packagePath := ""
	var packagesData []byte
	switch raw[0] {
	case '[':
		packagesData = raw
	case '{':
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return nil, "", fmt.Errorf("invalid Composer installed metadata: %w", err)
		}
		packagesData = bytes.TrimSpace(envelope["packages"])
		packagePath = "/packages"
	default:
		return nil, "", errors.New("invalid Composer installed metadata shape")
	}
	if len(packagesData) == 0 || packagesData[0] != '[' {
		return nil, "", errors.New("Composer installed metadata has no package array")
	}
	var packages []installedPackage
	if err := json.Unmarshal(packagesData, &packages); err != nil {
		return nil, "", fmt.Errorf("invalid Composer installed packages: %w", err)
	}
	if len(packages) > maxInstalledPackages {
		return nil, "", errors.New("Composer installed metadata has too many packages")
	}
	return packages, packagePath, nil
}

// InstalledPackageManifestPaths maps packages with a conventional in-vendor
// install path to their package-owned composer.json. Packages with null or
// custom installer paths remain unverified.
func InstalledPackageManifestPaths(data []byte, metadataPath string) map[string]string {
	result := map[string]string{}
	if !IsInstalledManifestPath(metadataPath) || len(data) > MaxInstalledJSONBytes {
		return result
	}
	packages, _, err := parseInstalledPackages(data)
	if err != nil {
		return result
	}
	composerDir := path.Dir(metadataPath)
	vendorDir := path.Dir(composerDir)
	for _, pkg := range packages {
		if !validInstalledPackageName(pkg.Name) || pkg.InstallPath == "" || len(pkg.InstallPath) > 1024 || path.IsAbs(pkg.InstallPath) || strings.ContainsAny(pkg.InstallPath, "\\\x00\r\n") {
			continue
		}
		installedDir := path.Clean(path.Join(composerDir, pkg.InstallPath))
		if installedDir != path.Join(vendorDir, pkg.Name) {
			continue
		}
		result[strings.ToLower(pkg.Name)] = path.Join(installedDir, "composer.json")
	}
	return result
}

func validInstalledPackageName(name string) bool {
	return len(name) <= 256 && installedPackageName.MatchString(name)
}

func validInstalledVersion(version string) bool {
	if version == "" || len(version) > 256 {
		return false
	}
	for _, char := range version {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func appendInstalledCondition(existing, clause string) string {
	if existing == "" {
		return clause
	}
	return existing + " && " + clause
}

func installedPointerToken(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}
