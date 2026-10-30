package swiftpm

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

type lockfile struct {
	Version int   `json:"version"`
	Pins    []pin `json:"pins"`
	Object  struct {
		Pins []pin `json:"pins"`
	} `json:"object"`
}

type pin struct {
	Identity      string `json:"identity"`
	Package       string `json:"package"`
	Kind          string `json:"kind"`
	Location      string `json:"location"`
	RepositoryURL string `json:"repositoryURL"`
	State         struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
		Branch   string `json:"branch"`
	} `json:"state"`
}

var revisionPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid Package.resolved: %w", err)
	}
	if lock.Version < 1 || lock.Version > 3 {
		return model.Document{}, fmt.Errorf("unsupported Package.resolved version %d", lock.Version)
	}
	doc := common.NewDocument(file, project, "swiftpm", data)
	doc.Coverage.GraphState = "unknown"
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "graph_unavailable"})
	pins := lock.Pins
	if lock.Version == 1 {
		pins = lock.Object.Pins
	}
	for i, p := range pins {
		name := p.Identity
		location := p.Location
		if lock.Version == 1 {
			name = p.Package
			location = p.RepositoryURL
		}
		if name == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency"})
			continue
		}
		ref := "swiftpm:" + common.ID(fmt.Sprintf("%s|%s|%s|%s", name, p.State.Version, p.State.Revision, location))
		ev := common.Evidence(file, "swiftpm-lock", fmt.Sprintf("/pins/%d", i), data)
		if lock.Version == 1 {
			ev.Pointer = fmt.Sprintf("/object/pins/%d", i)
		}
		component := model.Component{ID: ref, Kind: "package", Name: name, Version: p.State.Version, Evidence: []model.Evidence{ev}}
		clean := safeurl.Clean(location)
		revision := p.State.Revision
		if !revisionPattern.MatchString(revision) {
			revision = ""
		}
		if clean != "" && p.State.Version != "" {
			component.PURL = swiftPURL(name, p.State.Version, clean)
		}
		doc.Components = append(doc.Components, component)
		kind := p.Kind
		if lock.Version == 1 {
			kind = "remoteSourceControl"
		}
		switch kind {
		case "remoteSourceControl":
			if clean == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: name})
				continue
			}
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "vcs", SafeURL: clean, Revision: revision, Status: "declared", Evidence: ev})
		case "localSourceControl":
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
		case "registry":
			if clean == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
			} else {
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "declared_registry", SafeURL: clean, Status: "declared", Evidence: ev})
			}
		default:
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func swiftPURL(name, version, source string) string {
	u, err := url.Parse(source)
	if err != nil || u.Host == "" {
		return ""
	}
	segments := strings.Split(strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/"), "/")
	if len(segments) == 0 || !strings.EqualFold(segments[len(segments)-1], name) {
		return ""
	}
	namespace := u.Host
	for _, segment := range segments[:len(segments)-1] {
		namespace += "/" + url.PathEscape(segment)
	}
	return "pkg:swift/" + namespace + "/" + url.PathEscape(name) + "@" + url.PathEscape(version)
}
