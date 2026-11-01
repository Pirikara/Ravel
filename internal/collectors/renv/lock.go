package renv

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

const maxLockBytes = 32 << 20

var packageName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]{0,127}$`)
var remotePart = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var remoteSHA = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

type lockfile struct {
	R struct {
		Repositories []struct {
			Name string `json:"Name"`
			URL  string `json:"URL"`
		} `json:"Repositories"`
	} `json:"R"`
	Packages map[string]json.RawMessage `json:"Packages"`
}

type packageRecord struct {
	Package        string          `json:"Package"`
	Version        string          `json:"Version"`
	Source         string          `json:"Source"`
	Repository     string          `json:"Repository"`
	RemoteURL      string          `json:"RemoteUrl"`
	RemoteType     string          `json:"RemoteType"`
	RemoteUsername string          `json:"RemoteUsername"`
	RemoteRepo     string          `json:"RemoteRepo"`
	RemoteSHA      string          `json:"RemoteSha"`
	Requirements   json.RawMessage `json:"Requirements"`
}

type packageEntry struct {
	id, name string
	record   packageRecord
	evidence model.Evidence
}

func CollectLock(filename, project string) (model.Document, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxLockBytes {
		return model.Document{}, errors.New("renv lockfile size is invalid or exceeds limit")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return model.Document{}, err
	}
	if len(data) > maxLockBytes {
		return model.Document{}, errors.New("renv lockfile exceeds size limit")
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid renv.lock JSON: %w", err)
	}
	if lock.Packages == nil {
		return model.Document{}, errors.New("renv.lock has no Packages map")
	}
	doc := common.NewDocument(filename, project, "renv", data)
	repositories := map[string]string{}
	for _, repository := range lock.R.Repositories {
		if repository.Name != "" {
			repositories[repository.Name] = safeurl.Clean(repository.URL)
		}
	}
	names := make([]string, 0, len(lock.Packages))
	for name := range lock.Packages {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := map[string]packageEntry{}
	for _, name := range names {
		var record packageRecord
		if err := json.Unmarshal(lock.Packages[name], &record); err != nil || !packageName.MatchString(name) || record.Package != name || !validVersion(record.Version) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_package_invalid", Name: name})
			continue
		}
		id := "renv:" + common.ID(filename+"\x00"+name+"\x00"+record.Version)
		evidence := common.Evidence(filename, "renv-lock", "/Packages/"+name, data)
		doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: name, Version: record.Version, Evidence: []model.Evidence{evidence}})
		entries[name] = packageEntry{id: id, name: name, record: record, evidence: evidence}
		addOrigin(&doc, entries[name], repositories)
		if len(entries) > 100000 {
			return model.Document{}, errors.New("renv.lock has too many package records")
		}
	}
	if len(entries) == 0 && len(names) > 0 {
		return model.Document{}, errors.New("renv.lock has no valid package records")
	}
	for _, name := range names {
		entry, ok := entries[name]
		if !ok {
			continue
		}
		if len(entry.record.Requirements) == 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_requirements_unavailable", Name: name})
			continue
		}
		var requirements []any
		if err := json.Unmarshal(entry.record.Requirements, &requirements); err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_requirements_invalid", Name: name})
			continue
		}
		for _, raw := range requirements {
			required, ok := raw.(string)
			if !ok || !packageName.MatchString(required) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_requirements_invalid", Name: name})
				continue
			}
			if required == "R" {
				continue
			}
			dependency, ok := entries[required]
			if !ok {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: required, Scope: name})
				continue
			}
			evidence := entry.evidence
			evidence.Pointer += "/Requirements/" + required
			doc.Edges = append(doc.Edges, model.Edge{From: entry.id, To: dependency.id, Kind: "requires", Condition: "dependency category unverified", Evidence: evidence})
		}
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "missing_direct_dependencies"},
		model.Issue{Code: "renv_distribution_origin_unverified"},
		model.Issue{Code: "manifest_freshness_unverified"})
	common.Finalize(&doc)
	return doc, nil
}

func validVersion(version string) bool {
	return version != "" && len(version) <= 128 && strings.IndexFunc(version, unicode.IsControl) < 0
}

func addOrigin(doc *model.Document, entry packageEntry, repositories map[string]string) {
	record := entry.record
	evidence := entry.evidence
	if record.RemoteURL != "" {
		if clean := safeurl.Clean(record.RemoteURL); clean != "" {
			revision := ""
			if remoteSHA.MatchString(record.RemoteSHA) {
				revision = strings.ToLower(record.RemoteSHA)
			}
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: entry.id, Kind: "vcs", SafeURL: clean, Revision: revision, Status: "declared", Evidence: evidence})
			return
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: entry.name})
		return
	}
	if strings.EqualFold(record.Source, "GitHub") && remotePart.MatchString(record.RemoteUsername) && remotePart.MatchString(record.RemoteRepo) {
		url := "https://github.com/" + record.RemoteUsername + "/" + record.RemoteRepo
		revision := ""
		if remoteSHA.MatchString(record.RemoteSHA) {
			revision = strings.ToLower(record.RemoteSHA)
		}
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: entry.id, Kind: "vcs", SafeURL: url, Revision: revision, Status: "declared", Evidence: evidence})
		return
	}
	if strings.EqualFold(record.Source, "Repository") || strings.EqualFold(record.Source, "CRAN") || repositories[record.Source] != "" {
		url := repositories[record.Repository]
		if url == "" && (strings.HasPrefix(record.Repository, "https://") || strings.HasPrefix(record.Repository, "http://")) {
			url = safeurl.Clean(record.Repository)
		}
		if url == "" {
			url = repositories[record.Source]
		}
		if url != "" {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: entry.id, Kind: "declared_registry", SafeURL: url, Status: "declared", Evidence: evidence})
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_repository_unresolved", Name: entry.name})
		}
		return
	}
	if strings.HasPrefix(record.Source, "https://") || strings.HasPrefix(record.Source, "http://") {
		if clean := safeurl.Clean(record.Source); clean != "" {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: entry.id, Kind: "download_url", SafeURL: clean, Status: "declared", Evidence: evidence})
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: entry.name})
		}
		return
	}
	if strings.HasPrefix(record.Source, "/") || strings.HasPrefix(record.Source, "./") || strings.HasPrefix(record.Source, "../") {
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: entry.id, Kind: "local", LocalPath: record.Source, Status: "declared", Evidence: evidence})
		return
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_source_unverified", Name: entry.name})
}
