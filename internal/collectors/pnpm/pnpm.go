package pnpm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/licensing"
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
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
		Directory string `yaml:"directory"`
		Type      string `yaml:"type"`
	} `yaml:"resolution"`
	OS                   []string          `yaml:"os"`
	CPU                  []string          `yaml:"cpu"`
	Libc                 stringOrStrings   `yaml:"libc"`
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

func (entry *packageEntry) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			field, value := node.Content[i].Value, node.Content[i+1]
			if field != "name" && field != "version" {
				continue
			}
			if value.Kind == yaml.AliasNode && value.Alias != nil {
				value = value.Alias
			}
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" && value.Tag != "!!null" {
				return fmt.Errorf("package metadata %s must be a string", field)
			}
		}
	}
	type plainEntry packageEntry
	var decoded plainEntry
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*entry = packageEntry(decoded)
	return nil
}

// pnpm lockfiles contain both libc: glibc and libc: [glibc]. Keep both
// representations without silently coercing booleans, numbers, or mappings.
type stringOrStrings []string

func (values *stringOrStrings) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		*values = []string{node.Value}
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("expected a string or string array for libc")
	}
	result := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return fmt.Errorf("expected strings in libc array")
		}
		result = append(result, item.Value)
	}
	*values = result
	return nil
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
				Evidence: common.Evidence(manifestPath, "pnpm-manifest", "/name", manifestData), Licenses: licensing.JSONFields(manifestData, common.Evidence(manifestPath, "pnpm-manifest", "", manifestData))}
			common.CollectNodeDevelopment(&doc, "root", manifestData, common.Evidence(manifestPath, "pnpm-manifest", "", manifestData))
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
		registryAliases := map[string][]occurrence{}
		for key, occ := range byKey {
			if _, _, host, ok := splitRegistryPackage(strings.SplitN(key, "(", 2)[0]); ok && occ.ref != "" {
				alias := strings.TrimPrefix(key, host+"/")
				registryAliases[alias] = append(registryAliases[alias], occ)
			}
		}
		resolve := func(name, version string) occurrence {
			// Alias references can contain the full target locator directly,
			// including its peer context, rather than a bare version.
			if occ, ok := byKey[version]; ok {
				return occ
			}
			key := name + "@" + version
			if strings.HasPrefix(version, "npm:") {
				key = strings.TrimPrefix(version, "npm:")
			}
			if occ, ok := byKey[key]; ok {
				return occ
			}
			if matches := registryAliases[key]; len(matches) == 1 {
				return matches[0]
			} else if len(matches) > 1 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: name})
				return occurrence{}
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
	identity, ok := identifyPackage(base, pkg)
	if !ok {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "invalid package key"})
		return occurrence{}
	}
	name, version := identity.name, identity.version
	ref := "pnpm:" + common.ID(fmt.Sprintf("%d|%s", documentIndex, key))
	ev := common.Evidence(file, "pnpm-lock", fmt.Sprintf("/documents/%d/packages/%s", documentIndex, key), data)
	platform := strings.Join(append(append(append([]string{}, pkg.OS...), pkg.CPU...), pkg.Libc...), "/")
	component := model.Component{ID: ref, Kind: "package", Name: name, Version: version, Platform: platform, Hashes: common.Integrity(pkg.Resolution.Integrity), Evidence: []model.Evidence{ev}}
	if identity.directory {
		component.Kind = "application"
		if component.Version == "" && !collectLocalIdentity(doc, file, identity.localPath, &component) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "local_package_identity_unresolved", Name: name})
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "version_unresolved", Name: name})
		}
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", LocalPath: identity.localPath, Status: "declared", Evidence: ev})
	} else if identity.localPath != "" {
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", LocalPath: identity.localPath, Status: "declared", Evidence: ev})
	} else if common.DefaultNpmRegistry(identity.tarball) {
		component.PURL = common.NpmPURL(name, version)
	} else if identity.tarball == "" && (identity.registryHost == "" || strings.EqualFold(identity.registryHost, "registry.npmjs.org")) {
		component.PURL = common.NpmPURL(name, version)
		component.PURLBasis = "ecosystem_inferred"
	}
	if component.Version == "" && !identity.directory {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "version_unresolved", Name: name})
	}
	doc.Components = append(doc.Components, component)
	if identity.registryHost != "" {
		origin := model.Origin{Occurrence: ref, Kind: "registry_identity", Target: identity.registryHost, Status: "declared", Evidence: ev}
		if strings.EqualFold(identity.registryHost, "registry.npmjs.org") && identity.tarball == "" {
			origin.SafeURL, origin.Status = "https://registry.npmjs.org", "inferred_from_registry_key"
		} else if identity.tarball == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "registry_url_unresolved", Name: name})
		}
		doc.Origins = append(doc.Origins, origin)
	}
	condition := ""
	if platform != "" {
		condition = "platform=" + platform
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: name})
	}
	if identity.localPath != "" {
		return occurrence{ref: ref, key: key, condition: condition, snapshot: snap}
	}
	if identity.tarball != "" {
		clean := safeurl.CleanNpmArtifact(identity.tarball, name, version)
		if clean == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: name})
		} else {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "download_url", SafeURL: clean, Status: "declared", Evidence: ev})
		}
	} else if identity.registryHost == "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
	}
	return occurrence{ref: ref, key: key, condition: condition, snapshot: snap}
}

type lockedIdentity struct {
	name, version, tarball, localPath, registryHost string
	directory                                       bool
}

func identifyPackage(base string, pkg packageEntry) (lockedIdentity, bool) {
	name, version, ok := splitPackage(base)
	identity := lockedIdentity{name: name, version: version, tarball: pkg.Resolution.Tarball}
	if !ok {
		identity.name, identity.version, identity.registryHost, ok = splitRegistryPackage(base)
	}
	if !ok {
		name, location, named := splitNamedLocation(base, "file:")
		if !named && strings.HasPrefix(base, "file:") {
			name, location, named = pkg.Name, strings.TrimPrefix(base, "file:"), true
		}
		if named && packageName.MatchString(name) {
			if location == "" || pkg.Resolution.Type == "directory" && pkg.Resolution.Directory != location {
				return lockedIdentity{}, false
			}
			identity.name, identity.version, identity.localPath = name, pkg.Version, location
			identity.directory = pkg.Resolution.Type == "directory" && pkg.Resolution.Directory == location
			ok = true
		}
	}
	if !ok {
		if name, location, named := splitNamedHTTP(base); named {
			identity.name, identity.version, ok = name, pkg.Version, true
			if identity.tarball == "" {
				identity.tarball = location
			}
		}
	}
	if !ok && packageName.MatchString(pkg.Name) {
		if identity.tarball == "" && isHTTP(base) {
			identity.tarball = base
		}
		if isHTTP(identity.tarball) || strings.HasPrefix(identity.tarball, "file:") {
			identity.name, identity.version, ok = pkg.Name, pkg.Version, true
		}
	}
	if !ok {
		return lockedIdentity{}, false
	}
	if !packageVersion.MatchString(identity.version) {
		identity.version = ""
	}
	if strings.HasPrefix(identity.tarball, "file:") {
		identity.localPath = strings.TrimPrefix(identity.tarball, "file:")
	}
	return identity, true
}

func splitNamedLocation(key, prefix string) (string, string, bool) {
	if len(key) < 2 {
		return "", "", false
	}
	at := strings.Index(key[1:], "@") + 1
	if at <= 0 || !packageName.MatchString(key[:at]) || !strings.HasPrefix(key[at+1:], prefix) {
		return "", "", false
	}
	return key[:at], strings.TrimPrefix(key[at+1:], prefix), true
}

func splitRegistryPackage(key string) (string, string, string, bool) {
	host, rest, found := strings.Cut(key, "/")
	if !found || strings.HasSuffix(host, ":") || strings.ContainsAny(host, "@\\?#\x00\r\n\t ") {
		return "", "", "", false
	}
	parsed, err := url.Parse("https://" + host)
	if err != nil || parsed.User != nil || strings.Trim(parsed.Hostname(), ".") == "" || parsed.Path != "" {
		return "", "", "", false
	}
	name, version, ok := splitPackage(rest)
	return name, version, host, ok
}

func isHTTP(location string) bool {
	return (strings.HasPrefix(location, "https://") || strings.HasPrefix(location, "http://")) && safeurl.Clean(location) != ""
}

func collectLocalIdentity(doc *model.Document, lockfile, directory string, component *model.Component) bool {
	data, input, err := common.ReadLocalNodeManifest(lockfile, directory)
	if err != nil {
		return false
	}
	var manifest struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.Name != component.Name || manifest.Version == "" {
		return false
	}
	component.Version = manifest.Version
	ev := common.Evidence(input, "pnpm-local-manifest", "/version", data)
	ev.Method = "source-analysis"
	component.Evidence = append(component.Evidence, ev)
	component.Licenses = licensing.JSONFields(data, ev)
	common.CollectNodeDevelopment(doc, component.ID, data, ev)
	doc.Sources = append(doc.Sources, input)
	return true
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

// A named URL pin is a distinct occurrence even when its declared version is
// also available from a registry. The URL itself is not a package version.
func splitNamedHTTP(key string) (string, string, bool) {
	if len(key) < 2 {
		return "", "", false
	}
	at := strings.Index(key[1:], "@") + 1
	if at <= 0 {
		return "", "", false
	}
	name, location := key[:at], key[at+1:]
	if !packageName.MatchString(name) || (!strings.HasPrefix(location, "https://") && !strings.HasPrefix(location, "http://")) || safeurl.Clean(location) == "" {
		return "", "", false
	}
	return name, location, true
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
