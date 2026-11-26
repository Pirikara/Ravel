package python

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/pelletier/go-toml/v2"
)

// Read adjacent project metadata without executing build hooks or resolving
// dynamic fields. This describes the application, never its dependencies.
func collectProjectDevelopment(doc *model.Document, lockfile string) {
	file := filepath.Join(filepath.Dir(lockfile), "pyproject.toml")
	info, err := os.Lstat(file)
	if os.IsNotExist(err) {
		return
	}
	issue := func() {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "development_source_unresolved", Scope: "root"})
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		issue()
		return
	}
	data, err := os.ReadFile(file)
	if err != nil {
		issue()
		return
	}
	type projectMetadata struct {
		Name       string            `toml:"name"`
		Version    string            `toml:"version"`
		URLs       map[string]string `toml:"urls"`
		Repository string            `toml:"repository"`
		Homepage   string            `toml:"homepage"`
		Dynamic    []string          `toml:"dynamic"`
	}
	var manifest struct {
		Project *projectMetadata `toml:"project"`
		Tool    struct {
			Poetry *projectMetadata `toml:"poetry"`
		} `toml:"tool"`
	}
	if toml.Unmarshal(data, &manifest) != nil {
		issue()
		return
	}
	metadata, pointer := manifest.Project, "/project"
	if metadata == nil {
		metadata, pointer = manifest.Tool.Poetry, "/tool/poetry"
	}
	if metadata == nil || !installedDistributionName.MatchString(metadata.Name) {
		return
	}
	doc.Sources = append(doc.Sources, file)
	evidence := common.Evidence(file, "python-project", pointer+"/name", data)
	evidence.Method = "source-analysis"
	version := metadata.Version
	if slices.Contains(metadata.Dynamic, "version") {
		version = ""
	}
	occurrence := "root"
	applications := 0
	for _, component := range doc.Components {
		if component.Kind != "application" {
			continue
		}
		applications++
		if normalized(component.Name) == normalized(metadata.Name) && (version == "" || component.Version == version) {
			occurrence = component.ID
		}
	}
	if applications > 0 && (applications != 1 || occurrence == "root") {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_identity_mismatch", Scope: "root", Name: metadata.Name})
		return
	}
	if occurrence == "root" {
		doc.Root = &model.ProjectIdentity{Name: metadata.Name, Version: version, Evidence: evidence}
	}
	urls := metadata.URLs
	urlPointer := pointer + "/urls/"
	if pointer == "/tool/poetry" {
		urls = map[string]string{"repository": metadata.Repository, "homepage": metadata.Homepage}
		urlPointer = pointer + "/"
	}
	if slices.Contains(metadata.Dynamic, "urls") {
		issue()
		return
	}
	keys := make([]string, 0, len(urls))
	for key := range urls {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	explicit := false
	for _, key := range keys {
		if !wheelSourceLabel(key) || urls[key] == "" {
			continue
		}
		e := evidence
		e.Pointer = urlPointer + strings.NewReplacer("~", "~0", "/", "~1").Replace(key)
		before := len(doc.Development)
		common.AddDevelopment(doc, occurrence, urls[key], "declared", e)
		explicit = explicit || len(doc.Development) > before
	}
	if explicit {
		return
	}
	for _, key := range keys {
		if normalizedProjectLabel(key) != "homepage" {
			continue
		}
		if value := common.RepositoryHomepage(urls[key]); value != "" {
			e := evidence
			e.Pointer = urlPointer + key
			common.AddDevelopment(doc, occurrence, value, "inferred_from_homepage", e)
		}
	}
}
