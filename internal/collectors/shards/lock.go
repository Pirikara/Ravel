package shards

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

const maxLockBytes = 16 << 20
const maxManifestBytes = 2 << 20

var shardName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}$`)
var repositoryPart = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var revisionPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

type lockShard struct {
	Git       string `yaml:"git"`
	GitHub    string `yaml:"github"`
	GitLab    string `yaml:"gitlab"`
	Bitbucket string `yaml:"bitbucket"`
	Codeberg  string `yaml:"codeberg"`
	Path      string `yaml:"path"`
	HG        string `yaml:"hg"`
	Fossil    string `yaml:"fossil"`
	Version   string `yaml:"version"`
	Commit    string `yaml:"commit"`
}

type lockfile struct {
	Version string               `yaml:"version"`
	Shards  map[string]lockShard `yaml:"shards"`
}

type manifest struct {
	Dependencies            map[string]yaml.Node `yaml:"dependencies"`
	DevelopmentDependencies map[string]yaml.Node `yaml:"development_dependencies"`
}

func CollectLock(filename, project string) (model.Document, error) {
	data, err := readBounded(filename, maxLockBytes)
	if err != nil {
		return model.Document{}, err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return model.Document{}, fmt.Errorf("invalid shard.lock YAML: %w", err)
	}
	if err := checkYAML(&node, 0, new(int)); err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := node.Decode(&lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid shard.lock content: %w", err)
	}
	if lock.Version != "1.0" && lock.Version != "2.0" {
		return model.Document{}, fmt.Errorf("unsupported shard.lock version %q", lock.Version)
	}
	if lock.Shards == nil {
		return model.Document{}, errors.New("shard.lock has no shards mapping")
	}
	doc := common.NewDocument(filename, project, "shards", data)
	names := make([]string, 0, len(lock.Shards))
	for name := range lock.Shards {
		names = append(names, name)
	}
	sort.Strings(names)
	ids := map[string]string{}
	for _, name := range names {
		entry := lock.Shards[name]
		version := entry.Version
		if version == "" && lock.Version == "1.0" && revisionPattern.MatchString(entry.Commit) {
			version = strings.ToLower(entry.Commit)
		}
		if !shardName.MatchString(name) || !validText(version, 128) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "shards_package_invalid", Name: name})
			continue
		}
		id := "shards:" + common.ID(filename+"\x00"+name+"\x00"+version)
		evidence := common.Evidence(filename, "shards-lock", "/shards/"+name, data)
		doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: name, Version: version, Evidence: []model.Evidence{evidence}})
		ids[name] = id
		addOrigin(&doc, id, name, entry, evidence)
		if len(doc.Components) > 100000 {
			return model.Document{}, errors.New("shard.lock has too many packages")
		}
	}
	manifestPath := filepath.Join(filepath.Dir(filename), "shard.yml")
	if info, err := os.Stat(manifestPath); err == nil && info.Mode().IsRegular() {
		if err := addManifest(&doc, manifestPath, ids); err != nil {
			return model.Document{}, err
		}
	} else {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "shards_transitive_graph_unavailable"},
		model.Issue{Code: "shards_distribution_bytes_unverified"},
		model.Issue{Code: "manifest_freshness_unverified"})
	common.Finalize(&doc)
	return doc, nil
}

func addManifest(doc *model.Document, filename string, ids map[string]string) error {
	data, err := readBounded(filename, maxManifestBytes)
	if err != nil {
		return err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return fmt.Errorf("invalid shard.yml YAML: %w", err)
	}
	if err := checkYAML(&node, 0, new(int)); err != nil {
		return err
	}
	var project manifest
	if err := node.Decode(&project); err != nil {
		return fmt.Errorf("invalid shard.yml content: %w", err)
	}
	doc.Sources = append(doc.Sources, filename)
	if project.Dependencies == nil && project.DevelopmentDependencies == nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	}
	for _, group := range []struct {
		name      string
		condition string
		deps      map[string]yaml.Node
	}{{"dependencies", "", project.Dependencies}, {"development_dependencies", "development", project.DevelopmentDependencies}} {
		names := make([]string, 0, len(group.deps))
		for name := range group.deps {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if !shardName.MatchString(name) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "shards_manifest_dependency_invalid"})
				continue
			}
			id := ids[name]
			if id == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name, Scope: group.name})
				continue
			}
			doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "direct", Condition: group.condition, Evidence: common.Evidence(filename, "shards-manifest", "/"+group.name+"/"+name, data)})
		}
	}
	return nil
}

func addOrigin(doc *model.Document, id, name string, entry lockShard, evidence model.Evidence) {
	sources := []string{entry.Git, entry.GitHub, entry.GitLab, entry.Bitbucket, entry.Codeberg, entry.Path, entry.HG, entry.Fossil}
	count := 0
	for _, source := range sources {
		if source != "" {
			count++
		}
	}
	if count != 1 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "shards_source_unresolved", Name: name})
		return
	}
	if entry.Path != "" {
		if validText(entry.Path, 1024) {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "local", LocalPath: entry.Path, Status: "declared", Evidence: evidence})
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "shards_source_unresolved", Name: name})
		}
		return
	}
	raw := entry.Git
	if raw == "" {
		raw = entry.HG
	}
	if raw == "" {
		raw = entry.Fossil
	}
	for _, short := range []struct{ host, source string }{{"github.com", entry.GitHub}, {"gitlab.com", entry.GitLab}, {"bitbucket.org", entry.Bitbucket}, {"codeberg.org", entry.Codeberg}} {
		if short.source == "" {
			continue
		}
		parts := strings.Split(short.source, "/")
		if len(parts) != 2 || !repositoryPart.MatchString(parts[0]) || !repositoryPart.MatchString(parts[1]) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "shards_source_unresolved", Name: name})
			return
		}
		raw = "https://" + short.host + "/" + parts[0] + "/" + parts[1]
	}
	clean := safeurl.Clean(raw)
	if clean == "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "shards_source_unresolved", Name: name})
		return
	}
	revision := strings.ToLower(entry.Commit)
	if !revisionPattern.MatchString(revision) {
		revision = ""
		if index := strings.LastIndex(entry.Version, "+git.commit."); index >= 0 {
			candidate := entry.Version[index+len("+git.commit."):]
			if revisionPattern.MatchString(candidate) {
				revision = strings.ToLower(candidate)
			}
		}
	}
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "vcs", SafeURL: clean, Revision: revision, Status: "declared", Evidence: evidence})
}

func readBounded(filename string, limit int64) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("Shards input size is invalid or exceeds limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || int64(len(data)) > limit {
		return nil, errors.New("Shards input exceeds size limit")
	}
	return data, nil
}

func validText(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.IndexFunc(value, unicode.IsControl) < 0
}

func checkYAML(node *yaml.Node, depth int, count *int) error {
	*count = *count + 1
	if depth > 64 || *count > 200000 {
		return errors.New("Shards YAML exceeds nesting or node limit")
	}
	if node.Kind == yaml.AliasNode {
		return errors.New("Shards YAML aliases are unsupported")
	}
	for _, child := range node.Content {
		if err := checkYAML(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}
