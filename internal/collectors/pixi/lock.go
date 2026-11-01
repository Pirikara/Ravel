package pixi

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
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

var namePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,255}$`)
var scopePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
var md5Pattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
var revisionPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
var pythonSeparators = regexp.MustCompile(`[-_.]+`)

type packageRef struct {
	Conda string `yaml:"conda"`
	PyPI  string `yaml:"pypi"`
}

type packageRecord struct {
	packageRef `yaml:",inline"`
	Kind       string   `yaml:"kind"`
	URL        string   `yaml:"url"`
	Name       string   `yaml:"name"`
	Version    string   `yaml:"version"`
	Build      string   `yaml:"build"`
	Subdir     string   `yaml:"subdir"`
	SHA256     string   `yaml:"sha256"`
	MD5        string   `yaml:"md5"`
	Depends    []string `yaml:"depends"`
	Requires   []string `yaml:"requires_dist"`
}

type environment struct {
	Packages map[string][]packageRef `yaml:"packages"`
}

type lockfile struct {
	Version      int                    `yaml:"version"`
	Environments map[string]environment `yaml:"environments"`
	Packages     []packageRecord        `yaml:"packages"`
}

type resolvedRecord struct {
	manager, locator, name, version, subdir string
	fields                                  packageRecord
	index                                   int
}

type occurrence struct {
	record   resolvedRecord
	id, env  string
	platform string
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
		return model.Document{}, errors.New("pixi.lock size is invalid or exceeds limit")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return model.Document{}, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return model.Document{}, fmt.Errorf("invalid pixi.lock YAML: %w", err)
	}
	if err := checkYAML(&root, 0, new(int)); err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := root.Decode(&lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid pixi.lock content: %w", err)
	}
	if lock.Version != 6 && lock.Version != 7 {
		return model.Document{}, fmt.Errorf("unsupported pixi.lock version %d", lock.Version)
	}
	if lock.Environments == nil || lock.Packages == nil {
		return model.Document{}, errors.New("pixi.lock lacks environments or packages")
	}
	doc := common.NewDocument(filename, project, "pixi", data)
	records := map[string]resolvedRecord{}
	for index, fields := range lock.Packages {
		manager, locator := packageLocator(fields.packageRef)
		if manager == "" && (fields.Kind == "conda" || fields.Kind == "pypi") {
			manager, locator = fields.Kind, fields.URL
		}
		if manager == "" || locator == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_package_unhandled", Name: fmt.Sprint(index)})
			continue
		}
		name, version, subdir := fields.Name, fields.Version, fields.Subdir
		if manager == "conda" {
			artifactName, artifactVersion, artifactSubdir := condaArtifact(locator)
			if name == "" {
				name = artifactName
			}
			if version == "" {
				version = artifactVersion
			}
			if subdir == "" {
				subdir = artifactSubdir
			}
		}
		if !namePattern.MatchString(name) || !validVersion(version) || manager == "conda" && !scopePattern.MatchString(subdir) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_package_identity_unresolved", Name: fmt.Sprint(index)})
			continue
		}
		key := manager + "\x00" + locator
		if _, exists := records[key]; exists {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_duplicate_package_record", Name: name})
			continue
		}
		records[key] = resolvedRecord{manager: manager, locator: locator, name: name, version: version, subdir: subdir, fields: fields, index: index}
	}
	environmentNames := make([]string, 0, len(lock.Environments))
	for name := range lock.Environments {
		environmentNames = append(environmentNames, name)
	}
	sort.Strings(environmentNames)
	byScope := map[string]map[string][]occurrence{}
	byScopePyPI := map[string]map[string][]occurrence{}
	var occurrences []occurrence
	seen := map[string]bool{}
	platforms := map[string]bool{}
	for _, envName := range environmentNames {
		if !scopePattern.MatchString(envName) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_environment_invalid"})
			continue
		}
		env := lock.Environments[envName]
		platformNames := make([]string, 0, len(env.Packages))
		for platform := range env.Packages {
			platformNames = append(platformNames, platform)
		}
		sort.Strings(platformNames)
		for _, platform := range platformNames {
			if !scopePattern.MatchString(platform) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_platform_invalid", Name: envName})
				continue
			}
			platforms[platform] = true
			scope := envName + "\x00" + platform
			if byScope[scope] == nil {
				byScope[scope] = map[string][]occurrence{}
				byScopePyPI[scope] = map[string][]occurrence{}
			}
			for index, ref := range env.Packages[platform] {
				manager, locator := packageLocator(ref)
				record, found := records[manager+"\x00"+locator]
				if !found || manager == "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_selected_package_unresolved", Name: envName, Scope: platform})
					continue
				}
				selection := scope + "\x00" + manager + "\x00" + locator
				if seen[selection] {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_duplicate_selection", Name: record.name, Scope: platform})
					continue
				}
				seen[selection] = true
				id := "pixi:" + common.ID(filename+"\x00"+selection)
				evidence := common.Evidence(filename, "pixi-lock", fmt.Sprintf("/environments/%s/packages/%s/%d", envName, platform, index), data)
				context := "environment=" + envName + ";manager=" + manager
				if record.subdir != "" {
					context += ";artifact-subdir=" + record.subdir
				}
				component := model.Component{ID: id, Kind: "package", Name: record.name, Version: record.version, Platform: platform, Context: context, Evidence: []model.Evidence{evidence, common.Evidence(filename, "pixi-lock", fmt.Sprintf("/packages/%d", record.index), data)}}
				if manager == "pypi" && officialPyPI(locator) {
					component.PURL = packageurl.NewPackageURL("pypi", "", pythonSeparators.ReplaceAllString(strings.ToLower(record.name), "-"), record.version, nil, "").ToString()
				}
				addHashes(&doc, &component, record)
				addOrigin(&doc, id, record, evidence)
				doc.Components = append(doc.Components, component)
				occ := occurrence{record: record, id: id, env: envName, platform: platform, evidence: evidence}
				occurrences = append(occurrences, occ)
				byScope[scope][record.name] = append(byScope[scope][record.name], occ)
				byScopePyPI[scope][normalizePyPIName(record.name)] = append(byScopePyPI[scope][normalizePyPIName(record.name)], occ)
				if len(occurrences) > 100000 {
					return model.Document{}, errors.New("pixi.lock has too many selected packages")
				}
			}
		}
	}
	for platform := range platforms {
		doc.Coverage.Platforms = append(doc.Coverage.Platforms, platform)
	}
	sort.Strings(doc.Coverage.Platforms)
	for _, parent := range occurrences {
		requirements := parent.record.fields.Depends
		if parent.record.manager == "pypi" {
			requirements = parent.record.fields.Requires
		}
		for _, spec := range requirements {
			name := requirementName(spec)
			if name == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_requirement_invalid", Name: parent.record.name})
				continue
			}
			if strings.HasPrefix(name, "__") {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_virtual_requirement_unresolved", Name: name, Scope: parent.platform})
				continue
			}
			matches := byScope[parent.env+"\x00"+parent.platform][name]
			if len(matches) == 0 && parent.record.manager == "pypi" {
				matches = byScopePyPI[parent.env+"\x00"+parent.platform][normalizePyPIName(name)]
			}
			if len(matches) == 0 {
				if parent.record.manager == "pypi" && strings.Contains(spec, ";") {
					continue
				}
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name, Scope: parent.env + "/" + parent.platform})
				continue
			}
			if len(matches) > 1 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: name, Scope: parent.env + "/" + parent.platform})
				continue
			}
			evidence := parent.evidence
			evidence.Pointer = fmt.Sprintf("/packages/%d/depends/%s", parent.record.index, name)
			doc.Edges = append(doc.Edges, model.Edge{From: parent.id, To: matches[0].id, Kind: "requires", Condition: "environment=" + parent.env + "; platform=" + parent.platform + "; constraint unverified", Evidence: evidence})
		}
	}
	if err := addManifest(&doc, filename, lock, byScope); err != nil {
		return model.Document{}, err
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "pixi_requirement_constraints_unverified"},
		model.Issue{Code: "pixi_distribution_bytes_unverified"},
		model.Issue{Code: "manifest_freshness_unverified"})
	common.Finalize(&doc)
	return doc, nil
}

func packageLocator(ref packageRef) (string, string) {
	if ref.Conda != "" && ref.PyPI == "" {
		return "conda", ref.Conda
	}
	if ref.PyPI != "" && ref.Conda == "" {
		return "pypi", ref.PyPI
	}
	return "", ""
}

func condaArtifact(locator string) (name, version, subdir string) {
	parsed, err := url.Parse(locator)
	if err != nil || parsed.Host == "" {
		return "", "", ""
	}
	filename := path.Base(parsed.Path)
	for _, suffix := range []string{".conda", ".tar.bz2"} {
		if strings.HasSuffix(filename, suffix) {
			filename = strings.TrimSuffix(filename, suffix)
			break
		}
	}
	last := strings.LastIndexByte(filename, '-')
	if last < 0 {
		return "", "", ""
	}
	previous := strings.LastIndexByte(filename[:last], '-')
	if previous < 0 {
		return "", "", ""
	}
	return filename[:previous], filename[previous+1 : last], path.Base(path.Dir(parsed.Path))
}

func validVersion(version string) bool {
	return version != "" && len(version) <= 128 && strings.IndexFunc(version, unicode.IsControl) < 0
}

func officialPyPI(locator string) bool {
	parsed, err := url.Parse(locator)
	return err == nil && parsed.Scheme == "https" && (parsed.Hostname() == "files.pythonhosted.org" || parsed.Hostname() == "pypi.org")
}

func normalizePyPIName(name string) string {
	return pythonSeparators.ReplaceAllString(strings.ToLower(name), "-")
}

func requirementName(spec string) string {
	value := strings.TrimSpace(spec)
	if value == "" {
		return ""
	}
	end := strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune("[<>=!~;", r) })
	if end >= 0 {
		value = value[:end]
	}
	if !namePattern.MatchString(value) {
		return ""
	}
	return value
}

func addHashes(doc *model.Document, component *model.Component, record resolvedRecord) {
	if sha256Pattern.MatchString(record.fields.SHA256) {
		component.Hashes = append(component.Hashes, model.Hash{Alg: "SHA-256", Content: strings.ToLower(record.fields.SHA256)})
	} else if record.fields.SHA256 != "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_hash_invalid", Name: record.name})
	}
	if md5Pattern.MatchString(record.fields.MD5) {
		component.Hashes = append(component.Hashes, model.Hash{Alg: "MD5", Content: strings.ToLower(record.fields.MD5)})
	} else if record.fields.MD5 != "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_hash_invalid", Name: record.name})
	}
}

func addOrigin(doc *model.Document, id string, record resolvedRecord, evidence model.Evidence) {
	locator := record.locator
	if strings.HasPrefix(locator, "git+") {
		parsed, err := url.Parse(strings.TrimPrefix(locator, "git+"))
		if err == nil && revisionPattern.MatchString(parsed.Fragment) {
			if clean := safeurl.Clean(locator); clean != "" {
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "vcs", SafeURL: clean, Revision: strings.ToLower(parsed.Fragment), Status: "declared", Evidence: evidence})
				return
			}
		}
	} else if !strings.ContainsAny(locator, "${}") {
		if clean := safeurl.Clean(locator); clean != "" {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "download_url", SafeURL: clean, Status: "declared", Evidence: evidence})
			return
		}
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_source_unresolved", Name: record.name})
}

func checkYAML(node *yaml.Node, depth int, count *int) error {
	*count = *count + 1
	if depth > 64 || *count > 300000 {
		return errors.New("pixi.lock YAML exceeds nesting or node limit")
	}
	if node.Kind == yaml.AliasNode {
		return errors.New("pixi.lock YAML aliases are unsupported")
	}
	for _, child := range node.Content {
		if err := checkYAML(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}
