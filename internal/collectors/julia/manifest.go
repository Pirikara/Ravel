package julia

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

	"github.com/pelletier/go-toml/v2"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

const maxManifestBytes = 32 << 20
const maxProjectBytes = 1 << 20

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var packageName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,127}$`)

type packageEntry struct {
	name, uuid, id string
	fields         map[string]any
	evidence       model.Evidence
}

func CollectManifest(filename, project string) (model.Document, error) {
	data, err := readBounded(filename, maxManifestBytes)
	if err != nil {
		return model.Document{}, err
	}
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return model.Document{}, fmt.Errorf("invalid Julia manifest TOML: %w", err)
	}
	format, _ := raw["manifest_format"].(string)
	var groups map[string]any
	var pointerPrefix string
	switch {
	case strings.HasPrefix(format, "2."):
		groups, _ = raw["deps"].(map[string]any)
		pointerPrefix = "/deps"
	case format == "" || strings.HasPrefix(format, "1."):
		groups = raw
	default:
		return model.Document{}, fmt.Errorf("unsupported Julia manifest format %q", format)
	}
	if groups == nil {
		return model.Document{}, errors.New("Julia manifest has no dependency entries")
	}
	doc := common.NewDocument(filename, project, "julia", data)
	baseEvidence := common.Evidence(filename, "julia-manifest", "", data)
	names := make([]string, 0, len(groups))
	for name := range groups {
		if name == "julia_version" || name == "manifest_format" || name == "project_hash" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var entries []packageEntry
	for _, name := range names {
		if !packageName.MatchString(name) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "julia_manifest_entry_invalid", Name: name})
			continue
		}
		var records []any
		switch value := groups[name].(type) {
		case []any:
			records = value
		case map[string]any:
			records = []any{value}
		default:
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "julia_manifest_entry_invalid", Name: name})
			continue
		}
		for i, record := range records {
			fields, ok := record.(map[string]any)
			if !ok {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "julia_manifest_entry_invalid", Name: name})
				continue
			}
			uuid, _ := fields["uuid"].(string)
			version, _ := fields["version"].(string)
			if !uuidPattern.MatchString(uuid) || version != "" && !validVersion(version) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "julia_manifest_entry_invalid", Name: name})
				continue
			}
			evidence := baseEvidence
			evidence.Pointer = fmt.Sprintf("%s/%s/%d", pointerPrefix, name, i)
			id := "julia:" + common.ID(filename+"\x00"+name+"\x00"+uuid+"\x00"+fmt.Sprint(i))
			kind := "package"
			if version == "" {
				kind = "module"
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "version_unresolved", Name: name})
			}
			component := model.Component{ID: id, Kind: kind, Name: name, Version: version, Context: "uuid=" + strings.ToLower(uuid), Evidence: []model.Evidence{evidence}}
			if path, ok := fields["path"].(string); ok && path != "" {
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "local", LocalPath: path, Status: "declared", Evidence: evidence})
			}
			if url, ok := fields["repo-url"].(string); ok && url != "" {
				if clean := safeurl.Clean(url); clean != "" {
					rev, _ := fields["repo-rev"].(string)
					doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "vcs", SafeURL: clean, Revision: rev, Status: "declared", Evidence: evidence})
				} else {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: name})
				}
			}
			doc.Components = append(doc.Components, component)
			entries = append(entries, packageEntry{name: name, uuid: strings.ToLower(uuid), id: id, fields: fields, evidence: evidence})
			if len(entries) > 100000 {
				return model.Document{}, errors.New("Julia manifest has too many entries")
			}
		}
	}
	if len(entries) == 0 && len(names) > 0 {
		return model.Document{}, errors.New("Julia manifest has no valid package entries")
	}
	byName, byUUID := map[string][]packageEntry{}, map[string][]packageEntry{}
	for _, entry := range entries {
		byName[entry.name] = append(byName[entry.name], entry)
		byUUID[entry.uuid] = append(byUUID[entry.uuid], entry)
	}
	for _, entry := range entries {
		addDependencies(&doc, entry, "deps", false, byName, byUUID)
		if _, hasWeak := entry.fields["weakdeps"]; hasWeak {
			addDependencies(&doc, entry, "weakdeps", true, byName, byUUID)
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "target_conditions_unresolved", Name: entry.name})
		}
	}
	projectPath := companionProject(filename)
	if projectPath != "" {
		if err := addProjectDeps(&doc, projectPath, byUUID); err != nil {
			return model.Document{}, err
		}
	} else {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "manifest_freshness_unverified"},
		model.Issue{Code: "julia_distribution_origin_unverified"})
	common.Finalize(&doc)
	return doc, nil
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
		return nil, errors.New("Julia TOML input size is invalid or exceeds limit")
	}
	data := make([]byte, info.Size())
	_, err = io.ReadFull(file, data)
	return data, err
}

func validVersion(value string) bool {
	return value != "" && len(value) <= 128 && strings.IndexFunc(value, unicode.IsControl) < 0
}

func companionProject(filename string) string {
	name := "Project.toml"
	if strings.HasPrefix(filepath.Base(filename), "JuliaManifest") {
		name = "JuliaProject.toml"
	}
	path := filepath.Join(filepath.Dir(filename), name)
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
		return path
	}
	return ""
}

func addProjectDeps(doc *model.Document, filename string, byUUID map[string][]packageEntry) error {
	data, err := readBounded(filename, maxProjectBytes)
	if err != nil {
		return err
	}
	var project map[string]any
	if err := toml.Unmarshal(data, &project); err != nil {
		return fmt.Errorf("invalid Julia project TOML: %w", err)
	}
	doc.Sources = append(doc.Sources, filename)
	deps, _ := project["deps"].(map[string]any)
	if deps == nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
		return nil
	}
	evidence := common.Evidence(filename, "julia-project", "/deps", data)
	for name, raw := range deps {
		uuid, ok := raw.(string)
		if !ok || !uuidPattern.MatchString(uuid) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
			continue
		}
		matches := byUUID[strings.ToLower(uuid)]
		if len(matches) != 1 || matches[0].name != name {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
			continue
		}
		itemEvidence := evidence
		itemEvidence.Pointer = "/deps/" + name
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: matches[0].id, Kind: "direct", Evidence: itemEvidence})
	}
	if _, hasExtras := project["extras"]; hasExtras {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "target_conditions_unresolved", Name: "project extras"})
	}
	return nil
}

func addDependencies(doc *model.Document, parent packageEntry, field string, weak bool, byName, byUUID map[string][]packageEntry) {
	raw, exists := parent.fields[field]
	if !exists {
		return
	}
	requests := map[string]string{}
	switch deps := raw.(type) {
	case []any:
		for _, item := range deps {
			name, ok := item.(string)
			if !ok || !packageName.MatchString(name) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "julia_dependency_invalid", Name: parent.name})
				continue
			}
			requests[name] = ""
		}
	case map[string]any:
		for name, item := range deps {
			uuid, ok := item.(string)
			if !ok || !packageName.MatchString(name) || !uuidPattern.MatchString(uuid) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "julia_dependency_invalid", Name: parent.name})
				continue
			}
			requests[name] = strings.ToLower(uuid)
		}
	default:
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "julia_dependency_invalid", Name: parent.name})
		return
	}
	for name, uuid := range requests {
		var matches []packageEntry
		if uuid != "" {
			for _, entry := range byUUID[uuid] {
				if entry.name == name {
					matches = append(matches, entry)
				}
			}
		} else {
			matches = byName[name]
		}
		if len(matches) == 0 {
			if !weak {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name, Scope: parent.name})
			}
			continue
		}
		if len(matches) > 1 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: name, Scope: parent.name})
			continue
		}
		evidence := parent.evidence
		evidence.Pointer += "/" + field + "/" + name
		condition := ""
		if weak {
			condition = "weak dependency"
		}
		doc.Edges = append(doc.Edges, model.Edge{From: parent.id, To: matches[0].id, Kind: "requires", Condition: condition, Evidence: evidence})
	}
}
