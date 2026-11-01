package rebar

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	packageurl "github.com/package-url/packageurl-go"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

const maxLockBytes = 16 << 20

var packageName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}$`)
var gitRevision = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

func CollectLock(filename, project string) (model.Document, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxLockBytes {
		return model.Document{}, errors.New("rebar.lock size is invalid or exceeds limit")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return model.Document{}, err
	}
	if len(data) > maxLockBytes {
		return model.Document{}, errors.New("rebar.lock exceeds size limit")
	}
	terms, err := parseTerms(data)
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid rebar.lock: %w", err)
	}
	if len(terms) < 1 || terms[0].kind != '{' || len(terms[0].items) != 2 || terms[0].at(0).kind != 's' || terms[0].at(1).kind != '[' {
		return model.Document{}, errors.New("rebar.lock has no dependency list")
	}
	version := terms[0].at(0).text()
	if version != "1.2.0" && version != "1.1.0" {
		return model.Document{}, fmt.Errorf("unsupported rebar.lock format %q", version)
	}
	doc := common.NewDocument(filename, project, "rebar", data)
	entries := terms[0].at(1).items
	for index, entry := range entries {
		if entry.kind != '{' || len(entry.items) != 3 || entry.at(0).kind != 'b' || entry.at(1).kind != '{' || entry.at(2).kind != 'i' {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rebar_lock_entry_invalid", Name: fmt.Sprint(index)})
			continue
		}
		alias := entry.at(0).text()
		level, err := strconv.ParseUint(entry.at(2).text(), 10, 32)
		if !packageName.MatchString(alias) || err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rebar_lock_entry_invalid", Name: fmt.Sprint(index)})
			continue
		}
		source := entry.at(1)
		if source.at(0).kind != 'a' {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rebar_lock_entry_invalid", Name: alias})
			continue
		}
		id := "rebar:" + common.ID(filename+"\x00"+alias+"\x00"+fmt.Sprint(index))
		evidence := common.Evidence(filename, "rebar-lock", fmt.Sprintf("/entries/%d", index), data)
		component := model.Component{ID: id, Kind: "package", Name: alias, Context: fmt.Sprintf("lock-depth=%d", level), Evidence: []model.Evidence{evidence}}
		switch source.at(0).text() {
		case "pkg":
			if len(source.items) != 3 || source.at(1).kind != 'b' || source.at(2).kind != 'b' || !packageName.MatchString(source.at(1).text()) || !validVersion(source.at(2).text()) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rebar_lock_entry_invalid", Name: alias})
				continue
			}
			component.Name = source.at(1).text()
			component.Version = source.at(2).text()
			component.PURL = packageurl.NewPackageURL("hex", "", component.Name, component.Version, nil, "").ToString()
			if alias != component.Name {
				component.Context += "; lock-alias=" + alias
			}
		case "git":
			if len(source.items) != 3 || source.at(1).kind != 's' || source.at(2).kind != '{' || len(source.at(2).items) != 2 || source.at(2).at(0).kind != 'a' || source.at(2).at(0).text() != "ref" || !gitRevision.MatchString(source.at(2).at(1).text()) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rebar_lock_entry_invalid", Name: alias})
				continue
			}
			clean := safeurl.Clean(source.at(1).text())
			if clean == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: alias})
				continue
			}
			component.Version = strings.ToLower(source.at(2).at(1).text())
			component.Context += "; source=git"
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "vcs", SafeURL: clean, Revision: component.Version, Status: "declared", Evidence: evidence})
		default:
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rebar_lock_source_unhandled", Name: alias})
			continue
		}
		doc.Components = append(doc.Components, component)
		if len(doc.Components) > 100000 {
			return model.Document{}, errors.New("rebar.lock has too many entries")
		}
	}
	if len(doc.Components) == 0 && len(entries) > 0 {
		return model.Document{}, errors.New("rebar.lock has no supported package entries")
	}
	if len(terms) > 1 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rebar_package_hash_unrepresented"})
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "rebar_dependency_graph_unavailable"},
		model.Issue{Code: "missing_direct_dependencies"},
		model.Issue{Code: "rebar_distribution_origin_unverified"})
	common.Finalize(&doc)
	return doc, nil
}

func validVersion(version string) bool {
	return version != "" && len(version) <= 128 && strings.IndexFunc(version, unicode.IsControl) < 0
}
