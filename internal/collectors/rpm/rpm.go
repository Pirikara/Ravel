package rpm

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
	_ "modernc.org/sqlite" // Register the SQLite driver used by go-rpmdb.

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const MaxDatabaseBytes = 128 << 20
const maxPackages = 20000
const maxRequirements = 500000

// DatabasePaths lists installed RPM database locations in preference order.
var DatabasePaths = []string{
	"usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite", "usr/share/rpm/rpmdb.sqlite",
	"usr/lib/sysimage/rpm/Packages.db", "var/lib/rpm/Packages.db", "usr/share/rpm/Packages.db",
	"usr/lib/sysimage/rpm/Packages", "var/lib/rpm/Packages", "usr/share/rpm/Packages",
}

var (
	packageName  = regexp.MustCompile(`^[A-Za-z0-9_+][A-Za-z0-9._+%-]*$`)
	architecture = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
)

type installedPackage struct {
	name, version, arch, ref string
	provides, requires       []headerDependency
	metadataKnown            bool
	header                   *rpmdb.PackageInfo
}

type rpmProvider struct {
	ref     string
	version string
	flags   uint32
	known   bool
}

// Collect reads an RPM installed-package database from a filesystem tree.
// The database alone does not identify the distribution or repository.
func Collect(file, project string) (model.Document, error) {
	wal, err := os.Stat(file + "-wal")
	if err == nil && wal.Size() != 0 {
		return model.Document{}, errors.New("RPM SQLite database has an uncheckpointed WAL")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return model.Document{}, err
	}
	input, err := os.Open(file)
	if err != nil {
		return model.Document{}, err
	}
	defer input.Close()
	data, err := io.ReadAll(io.LimitReader(input, MaxDatabaseBytes+1))
	if err != nil {
		return model.Document{}, err
	}
	return CollectBytes(data, file, project)
}

// CollectBytes reads a database already verified from a container layer.
func CollectBytes(data []byte, source, project string) (model.Document, error) {
	if len(data) == 0 || len(data) > MaxDatabaseBytes {
		return model.Document{}, errors.New("RPM database is empty or exceeds size limit")
	}
	temp, err := os.CreateTemp("", "ravel-rpmdb-")
	if err != nil {
		return model.Document{}, err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return model.Document{}, err
	}
	if err := temp.Close(); err != nil {
		return model.Document{}, err
	}
	database, err := rpmdb.Open(temp.Name())
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid RPM database: %w", err)
	}
	defer database.Close()
	entries, err := database.ListPackages()
	if err != nil {
		return model.Document{}, fmt.Errorf("could not read RPM package headers: %w", err)
	}
	if len(entries) > maxPackages {
		return model.Document{}, errors.New("RPM database has too many packages")
	}
	dependencyHeaders := readDependencyHeaders(temp.Name(), data)
	hash := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "rpmdb", InputPath: source, InputDigest: digest, Method: "installed-database"}
	doc := common.NewDocument(source, project, "rpm", nil)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: "RPM database"})
	packages := make([]installedPackage, 0, len(entries))
	seenPackages := map[string]bool{}
	wantedFiles := map[string]bool{}
	requirementCount := 0
	for _, entry := range entries {
		if entry != nil && entry.Name == "gpg-pubkey" && entry.Arch == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rpm_key_record_skipped"})
			continue
		}
		if entry == nil || !packageName.MatchString(entry.Name) || entry.Version == "" || entry.Release == "" || strings.ContainsAny(entry.Version+entry.Release, " \t\r\n\x00/\\") || !architecture.MatchString(entry.Arch) {
			return model.Document{}, errors.New("RPM database contains invalid package identity")
		}
		version := entry.Version + "-" + entry.Release
		if entry.Epoch != nil && *entry.Epoch != 0 {
			if *entry.Epoch < 0 {
				return model.Document{}, errors.New("RPM package has invalid epoch")
			}
			version = strconv.Itoa(*entry.Epoch) + ":" + version
		}
		key := entry.Name + "\x00" + entry.Arch + "\x00" + version
		if seenPackages[key] {
			return model.Document{}, fmt.Errorf("duplicate installed RPM package %s:%s-%s", entry.Name, entry.Arch, version)
		}
		seenPackages[key] = true
		ref := "rpm:" + common.ID(key)
		epoch := 0
		if entry.Epoch != nil {
			epoch = *entry.Epoch
		}
		headerKey := entry.Name + "\x00" + strconv.Itoa(epoch) + ":" + entry.Version + "-" + entry.Release + "\x00" + entry.Arch
		header, known := dependencyHeaders[headerKey]
		if known && (!sameDependencyNames(header.provides, entry.Provides) || !sameDependencyNames(header.requires, entry.Requires)) {
			known = false
		}
		if !known {
			header.provides = namesWithoutMetadata(entry.Provides)
			header.requires = namesWithoutMetadata(entry.Requires)
		}
		packages = append(packages, installedPackage{name: entry.Name, version: version, arch: entry.Arch, ref: ref, provides: header.provides, requires: header.requires, metadataKnown: known, header: entry})
		for _, requirement := range header.requires {
			if validRPMFileRequirement(requirement.name) {
				wantedFiles[requirement.name] = true
			}
		}
		doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: entry.Name, Version: version, Platform: entry.Arch, Context: "status=installed", Evidence: []model.Evidence{evidence}})
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ref, Kind: "installed", Evidence: evidence})
		requirementCount += len(entry.Requires)
		if requirementCount > maxRequirements {
			return model.Document{}, errors.New("RPM database has too many requirements")
		}
	}
	providers := map[string][]rpmProvider{}
	providerCatalogComplete := true
	for _, pkg := range packages {
		if !pkg.metadataKnown {
			providerCatalogComplete = false
		}
		if !slices.ContainsFunc(pkg.provides, func(capability headerDependency) bool { return capability.name == pkg.name }) {
			providers[pkg.name] = append(providers[pkg.name], rpmProvider{ref: pkg.ref})
		}
		for _, capability := range pkg.provides {
			if capability.name != "" && len(capability.name) <= 512 {
				providers[capability.name] = append(providers[capability.name], rpmProvider{ref: pkg.ref, version: capability.version, flags: capability.flags, known: pkg.metadataKnown})
			}
		}
	}
	fileOwners, fileIssues := indexFileOwners(packages, wantedFiles)
	doc.Coverage.Issues = append(doc.Coverage.Issues, fileIssues...)
	for name, candidates := range fileOwners {
		providers[name] = append(providers[name], candidates...)
	}
	seenEdges := map[string]bool{}
	for _, pkg := range packages {
		externalRequirement := false
		constraintUnverified := false
		for _, requirement := range pkg.requires {
			evidenceRequirement := requirement.name
			if requirement.name == "" || len(requirement.name) > 512 || strings.ContainsAny(requirement.name, "\x00\r\n@#?") || strings.Contains(requirement.name, "://") {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rpm_requirement_unparsed", Name: pkg.name})
				continue
			}
			if strings.HasPrefix(requirement.name, "rpmlib(") {
				continue // Internal RPM feature supplied by the package manager.
			}
			if strings.HasPrefix(requirement.name, "(") {
				conditional, valid := parseSimpleRPMIf(requirement.name)
				if !valid {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rpm_requirement_unparsed", Name: requirement.name, Scope: pkg.name})
					continue
				}
				switch evaluateRPMGuard(conditional.guard, pkg.metadataKnown, providerCatalogComplete, providers) {
				case rpmGuardAbsent:
					if !conditional.hasElse {
						continue // An implication with a false guard is satisfied.
					}
					requirement = conditional.fallback
				case rpmGuardUnknown:
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rpm_boolean_guard_unverified", Name: requirement.name, Scope: pkg.name})
					continue
				default:
					requirement = conditional.consequence
				}
			}
			externalRequirement = true
			fileRequirement := strings.HasPrefix(requirement.name, "/")
			if fileRequirement && !validRPMFileRequirement(requirement.name) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rpm_file_requirement_unresolved", Name: requirement.name, Scope: pkg.name})
				continue
			}
			matches := map[string]string{}
			selfSatisfied := false
			selfPossible := false
			for _, candidate := range providers[requirement.name] {
				condition, possible := rpmConstraint(requirement, pkg.metadataKnown, candidate)
				if !possible {
					continue
				}
				if candidate.ref == pkg.ref {
					selfSatisfied = selfSatisfied || condition == ""
					selfPossible = selfPossible || condition != ""
					continue
				}
				previous, exists := matches[candidate.ref]
				if !exists || previous != "" && condition == "" {
					matches[candidate.ref] = condition
				}
			}
			if selfSatisfied {
				continue // A package's own capability needs no dependency edge.
			}
			if len(matches) == 0 {
				if selfPossible {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dependency_constraint_unverified", Name: requirement.name, Scope: pkg.name})
					continue
				}
				code := "unresolved_dependency"
				if fileRequirement {
					code = "rpm_file_requirement_unresolved"
				}
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: requirement.name, Scope: pkg.name})
				continue
			}
			ambiguous := len(matches) > 1 || selfPossible
			if ambiguous {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: requirement.name, Scope: pkg.name})
			}
			for target, condition := range matches {
				if condition == "rpm_constraint=unverified" {
					constraintUnverified = true
				}
				if ambiguous {
					if condition != "" {
						condition += " && "
					}
					condition += "provider=ambiguous"
				}
				key := pkg.ref + "\x00" + target + "\x00" + evidenceRequirement
				if seenEdges[key] {
					continue
				}
				seenEdges[key] = true
				linked := evidence
				linked.Pointer = "requires/" + evidenceRequirement
				doc.Edges = append(doc.Edges, model.Edge{From: pkg.ref, To: target, Kind: "depends_on", Condition: condition, Evidence: linked})
			}
		}
		if constraintUnverified {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dependency_constraint_unverified", Name: pkg.name})
		}
		if externalRequirement && !pkg.metadataKnown {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rpm_dependency_flags_unavailable", Name: pkg.name})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func sameDependencyNames(dependencies []headerDependency, names []string) bool {
	return slices.EqualFunc(dependencies, names, func(dependency headerDependency, name string) bool {
		return dependency.name == name
	})
}

func namesWithoutMetadata(names []string) []headerDependency {
	result := make([]headerDependency, len(names))
	for i, name := range names {
		result[i].name = name
	}
	return result
}

// rpmConstraint only claims a versioned match when the provider offers an
// exact EVR and the comparison settles the requirement. Range offers and
// provider-side release omissions that can match multiple EVRs stay conditional.
func rpmConstraint(requirement headerDependency, known bool, provider rpmProvider) (string, bool) {
	if !known {
		return "rpm_constraint=unverified", true
	}
	if requirement.version == "" && requirement.flags&rpmSenseMask == 0 {
		return "", true
	}
	if !provider.known || requirement.version == "" || provider.version == "" {
		return "rpm_constraint=unverified", true
	}
	if requirement.flags&rpmSenseMask == 0 {
		return "rpm_constraint=unverified", true
	}
	if provider.flags&rpmSenseMask == rpmSenseEqual {
		if comparison, comparable := compareRPMProviderToRequirement(provider.version, requirement.version); comparable {
			switch {
			case comparison < 0:
				return "", requirement.flags&rpmSenseLess != 0
			case comparison > 0:
				return "", requirement.flags&rpmSenseGreater != 0
			default:
				return "", requirement.flags&rpmSenseEqual != 0
			}
		}
	}
	return "rpm_constraint=unverified", true
}
