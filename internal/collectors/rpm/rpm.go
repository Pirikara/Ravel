package rpm

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
	_ "modernc.org/sqlite" // Register the SQLite driver used by go-rpmdb.

	"ravel/internal/collectors/common"
	"ravel/internal/model"
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
	provides, requires       []string
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
	hash := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "rpmdb", InputPath: source, InputDigest: digest, Method: "installed-database"}
	doc := common.NewDocument(source, project, "rpm", nil)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: "RPM database"})
	packages := make([]installedPackage, 0, len(entries))
	seenPackages := map[string]bool{}
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
		packages = append(packages, installedPackage{name: entry.Name, version: version, arch: entry.Arch, ref: ref, provides: entry.Provides, requires: entry.Requires})
		doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: entry.Name, Version: version, Platform: entry.Arch, Context: "status=installed", Evidence: []model.Evidence{evidence}})
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ref, Kind: "installed", Evidence: evidence})
		requirementCount += len(entry.Requires)
		if requirementCount > maxRequirements {
			return model.Document{}, errors.New("RPM database has too many requirements")
		}
	}
	providers := map[string][]string{}
	for _, pkg := range packages {
		providers[pkg.name] = append(providers[pkg.name], pkg.ref)
		for _, capability := range pkg.provides {
			if capability != "" && len(capability) <= 512 {
				providers[capability] = append(providers[capability], pkg.ref)
			}
		}
	}
	seenEdges := map[string]bool{}
	for _, pkg := range packages {
		fileRequirement := false
		externalRequirement := false
		for _, requirement := range pkg.requires {
			if requirement == "" || len(requirement) > 512 || strings.ContainsAny(requirement, "\x00\r\n@#?") || strings.Contains(requirement, "://") {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rpm_requirement_unparsed", Name: pkg.name})
				continue
			}
			if strings.HasPrefix(requirement, "rpmlib(") {
				continue // Internal RPM feature supplied by the package manager.
			}
			externalRequirement = true
			if strings.HasPrefix(requirement, "/") {
				fileRequirement = true
				continue // File ownership is not available from this package view.
			}
			matches := map[string]bool{}
			for _, candidate := range providers[requirement] {
				if candidate != pkg.ref {
					matches[candidate] = true
				}
			}
			if len(matches) == 0 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: requirement, Scope: pkg.name})
				continue
			}
			condition := "rpm_constraint=unverified"
			if len(matches) > 1 {
				condition += " && provider=ambiguous"
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: requirement, Scope: pkg.name})
			}
			for target := range matches {
				key := pkg.ref + "\x00" + target + "\x00" + requirement
				if seenEdges[key] {
					continue
				}
				seenEdges[key] = true
				linked := evidence
				linked.Pointer = "requires/" + requirement
				doc.Edges = append(doc.Edges, model.Edge{From: pkg.ref, To: target, Kind: "depends_on", Condition: condition, Evidence: linked})
			}
		}
		if fileRequirement {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rpm_file_requirement_unresolved", Name: pkg.name})
		}
		if externalRequirement {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rpm_dependency_flags_unavailable", Name: pkg.name})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}
