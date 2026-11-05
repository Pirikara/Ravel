package pnpm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

type lockDocument struct {
	LockfileVersion      string                  `yaml:"lockfileVersion"`
	Importers            map[string]importer     `yaml:"importers"`
	Dependencies         map[string]imported     `yaml:"dependencies"`
	DevDependencies      map[string]imported     `yaml:"devDependencies"`
	OptionalDependencies map[string]imported     `yaml:"optionalDependencies"`
	Packages             map[string]packageEntry `yaml:"packages"`
	Snapshots            map[string]snapshot     `yaml:"snapshots"`
}

type importer struct {
	Dependencies               map[string]imported `yaml:"dependencies"`
	DevDependencies            map[string]imported `yaml:"devDependencies"`
	OptionalDependencies       map[string]imported `yaml:"optionalDependencies"`
	ConfigDependencies         map[string]imported `yaml:"configDependencies"`
	PackageManagerDependencies map[string]imported `yaml:"packageManagerDependencies"`
}

type imported struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

type packageEntry struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
	} `yaml:"resolution"`
	OS                   []string          `yaml:"os"`
	CPU                  []string          `yaml:"cpu"`
	Libc                 []string          `yaml:"libc"`
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type snapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type occurrence struct {
	ref, key, condition string
	snapshot            snapshot
}

var packageName = regexp.MustCompile(`^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+$`)
var packageVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]*$`)

func sameImporterSpecifiers(locked map[string]imported, declared map[string]string) bool {
	if len(locked) != len(declared) {
		return false
	}
	for name, specifier := range declared {
		entry, ok := locked[name]
		if !ok || entry.Specifier != specifier {
			return false
		}
	}
	return true
}

func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var documents []lockDocument
	for {
		var lock lockDocument
		err := decoder.Decode(&lock)
		if err == io.EOF {
			break
		}
		if err != nil {
			return model.Document{}, fmt.Errorf("invalid pnpm-lock.yaml: %w", err)
		}
		if !strings.HasPrefix(lock.LockfileVersion, "9.") && !strings.HasPrefix(lock.LockfileVersion, "6.") {
			return model.Document{}, fmt.Errorf("unsupported pnpm lockfile version %q", lock.LockfileVersion)
		}
		if strings.HasPrefix(lock.LockfileVersion, "9.") && len(lock.Importers) == 0 {
			return model.Document{}, fmt.Errorf("pnpm lockfile has no project importers")
		}
		documents = append(documents, lock)
	}
	if len(documents) == 0 {
		return model.Document{}, fmt.Errorf("empty pnpm lockfile")
	}
	doc := common.NewDocument(file, project, "pnpm", data)
	var manifest struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	manifestLoaded := false
	manifestPath := filepath.Join(filepath.Dir(file), "package.json")
	if manifestData, err := os.ReadFile(manifestPath); err == nil {
		doc.Sources = append(doc.Sources, manifestPath)
		if json.Unmarshal(manifestData, &manifest) == nil {
			manifestLoaded = true
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified"})
		}
		if manifestLoaded && manifest.Name != "" {
			doc.Root = &model.ProjectIdentity{Name: manifest.Name, Version: manifest.Version,
				Evidence: common.Evidence(manifestPath, "pnpm-manifest", "/name", manifestData)}
		}
	}
	if len(documents) > 1 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: "boot dependencies"})
	}
	for documentIndex, lock := range documents {
		byKey := map[string]occurrence{}
		if strings.HasPrefix(lock.LockfileVersion, "6.") {
			// pnpm 8 stores dependency edges on each package and may use top-level
			// dependency groups instead of an importers map for a single project.
			if len(lock.Importers) == 0 {
				lock.Importers = map[string]importer{".": {
					Dependencies: lock.Dependencies, DevDependencies: lock.DevDependencies,
					OptionalDependencies: lock.OptionalDependencies,
				}}
			}
			for key, pkg := range lock.Packages {
				normalized := strings.TrimPrefix(key, "/")
				if _, exists := byKey[normalized]; exists {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: normalized})
					continue
				}
				base := strings.SplitN(normalized, "(", 2)[0]
				snap := snapshot{Dependencies: pkg.Dependencies, OptionalDependencies: pkg.OptionalDependencies}
				byKey[normalized] = addPackage(&doc, file, data, documentIndex, key, base, pkg, snap)
			}
		} else {
			for key, snap := range lock.Snapshots {
				base := strings.SplitN(key, "(", 2)[0]
				pkg, exists := lock.Packages[base]
				if !exists {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "snapshot without package metadata"})
					continue
				}
				occ := addPackage(&doc, file, data, documentIndex, key, base, pkg, snap)
				byKey[key] = occ
			}
			for key, pkg := range lock.Packages {
				found := false
				for snapshotKey := range lock.Snapshots {
					if strings.SplitN(snapshotKey, "(", 2)[0] == key {
						found = true
						break
					}
				}
				if !found {
					byKey[key] = addPackage(&doc, file, data, documentIndex, key, key, pkg, snapshot{})
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unreachable_graph", Name: "package without snapshot"})
				}
			}
		}
		if documentIndex == 0 && manifestLoaded {
			if root, ok := lock.Importers["."]; ok &&
				(!sameImporterSpecifiers(root.Dependencies, manifest.Dependencies) ||
					!sameImporterSpecifiers(root.DevDependencies, manifest.DevDependencies) ||
					!sameImporterSpecifiers(root.OptionalDependencies, manifest.OptionalDependencies)) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified"})
			}
		}
		resolve := func(name, version string) occurrence {
			key := name + "@" + version
			if strings.HasPrefix(version, "npm:") {
				key = strings.TrimPrefix(version, "npm:")
			}
			if occ, ok := byKey[key]; ok {
				return occ
			}
			if strings.HasPrefix(version, "link:") || strings.HasPrefix(version, "workspace:") {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "local workspace dependency"})
				return occurrence{}
			}
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
			return occurrence{}
		}
		for _, occ := range byKey {
			for name, version := range occ.snapshot.Dependencies {
				if to := resolve(name, version); to.ref != "" {
					appendEdge(&doc, file, data, occ.ref, to.ref, "depends_on", join(occ.condition, to.condition))
				}
			}
			for name, version := range occ.snapshot.OptionalDependencies {
				if to := resolve(name, version); to.ref != "" {
					appendEdge(&doc, file, data, occ.ref, to.ref, "depends_on", join(occ.condition, to.condition, "optional"))
				}
			}
		}
		for path, importer := range lock.Importers {
			condition := ""
			if path != "." {
				condition = "workspace=" + path
			}
			if documentIndex < len(documents)-1 {
				condition = join(condition, "boot")
			}
			for _, group := range []map[string]imported{importer.Dependencies, importer.DevDependencies, importer.ConfigDependencies, importer.PackageManagerDependencies} {
				for name, item := range group {
					if to := resolve(name, item.Version); to.ref != "" {
						appendEdge(&doc, file, data, "root", to.ref, "direct", join(condition, to.condition))
					}
				}
			}
			for name, item := range importer.OptionalDependencies {
				if to := resolve(name, item.Version); to.ref != "" {
					appendEdge(&doc, file, data, "root", to.ref, "direct", join(condition, to.condition, "optional"))
				}
			}
			if condition != "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: path})
			}
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func addPackage(doc *model.Document, file string, data []byte, documentIndex int, key, base string, pkg packageEntry, snap snapshot) occurrence {
	name, version, ok := splitPackage(base)
	if !ok {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "invalid package key"})
		return occurrence{}
	}
	ref := "pnpm:" + common.ID(fmt.Sprintf("%d|%s", documentIndex, key))
	ev := common.Evidence(file, "pnpm-lock", fmt.Sprintf("/documents/%d/packages/%s", documentIndex, key), data)
	platform := strings.Join(append(append(append([]string{}, pkg.OS...), pkg.CPU...), pkg.Libc...), "/")
	component := model.Component{ID: ref, Kind: "package", Name: name, Version: version, Platform: platform, Hashes: common.Integrity(pkg.Resolution.Integrity), Evidence: []model.Evidence{ev}}
	if common.DefaultNpmRegistry(pkg.Resolution.Tarball) {
		component.PURL = common.NpmPURL(name, version)
	} else if pkg.Resolution.Tarball == "" {
		component.PURL = common.NpmPURL(name, version)
		component.PURLBasis = "ecosystem_inferred"
	}
	doc.Components = append(doc.Components, component)
	condition := ""
	if platform != "" {
		condition = "platform=" + platform
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: name})
	}
	if pkg.Resolution.Tarball != "" {
		clean := safeurl.Clean(pkg.Resolution.Tarball)
		if clean == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: name})
		} else {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "download_url", SafeURL: clean, Status: "declared", Evidence: ev})
		}
	} else {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
	}
	return occurrence{ref: ref, key: key, condition: condition, snapshot: snap}
}

func splitPackage(key string) (string, string, bool) {
	at := strings.LastIndex(key, "@")
	if at <= 0 || at == len(key)-1 {
		return "", "", false
	}
	name, version := key[:at], key[at+1:]
	if !packageName.MatchString(name) || !packageVersion.MatchString(version) {
		return "", "", false
	}
	return name, version, true
}

func appendEdge(doc *model.Document, file string, data []byte, from, to, kind, condition string) {
	doc.Edges = append(doc.Edges, model.Edge{From: from, To: to, Kind: kind, Condition: condition, Evidence: common.Evidence(file, "pnpm-lock", "/snapshots", data)})
	if condition != "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: to})
	}
}

func join(parts ...string) string {
	var nonempty []string
	for _, part := range parts {
		if part != "" {
			nonempty = append(nonempty, part)
		}
	}
	return strings.Join(nonempty, " && ")
}
