package export

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

func sourceDescription(o model.Origin, component model.Component) string {
	parts := []string{"Source kind: " + o.Kind}
	if clean := common.CleanOriginURL(o, component); clean != "" {
		parts = append(parts, "location: "+clean)
	}
	if o.VCSType != "" {
		parts = append(parts, "VCS: "+o.VCSType)
	}
	if o.Revision != "" {
		parts = append(parts, "revision: "+strconv.Quote(o.Revision))
	}
	if o.LocalPath != "" {
		parts = append(parts, "local path: "+strconv.Quote(o.LocalPath))
	}
	if o.Target != "" {
		parts = append(parts, "target: "+strconv.Quote(o.Target))
	}
	if o.Status != "" {
		parts = append(parts, "status: "+o.Status)
	}
	parts = append(parts, "artifact provenance not independently verified")
	return strings.Join(parts, "; ")
}

func packageSourceInfo(origins []model.Origin, component model.Component) string {
	set := map[string]bool{}
	for _, o := range origins {
		set[sourceDescription(o, component)] = true
	}
	rows := make([]string, 0, len(set))
	for row := range set {
		rows = append(rows, row)
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}

func packageDownloadLocation(origins []model.Origin, component model.Component) string {
	downloads := common.UniqueSourceLocations(origins, component)
	if len(downloads) == 1 {
		return downloads[0]
	}
	if len(downloads) > 1 {
		return "NOASSERTION"
	}
	vcs := map[string]bool{}
	for _, o := range origins {
		if o.Kind != "vcs" || o.Revision == "" {
			continue
		}
		if location := common.VCSLocation(o); location != "" {
			vcs[location] = true
		}
	}
	if len(vcs) == 1 {
		for location := range vcs {
			return location
		}
	}
	return "NOASSERTION"
}

func originReference(o model.Origin, component model.Component) (reference, bool) {
	clean := common.CleanOriginURL(o, component)
	if clean == "" {
		return reference{}, false
	}
	typ := ""
	switch o.Kind {
	case "declared_registry", "registry_identity", "download_url":
		typ = "distribution"
	case "vcs":
		typ = "vcs"
		if location := common.VCSLocation(o); location != "" {
			clean = location
		}
	case "podspec":
		typ = "build-meta"
	case "configured_repository":
		typ = "distribution"
	default:
		typ = "other"
	}
	return reference{Type: typ, URL: clean, Comment: sourceDescription(o, component)}, true
}
