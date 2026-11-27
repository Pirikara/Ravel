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

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
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
	if len(terms) < 1 {
		return model.Document{}, errors.New("rebar.lock has no dependency list")
	}
	var entries []term
	if terms[0].kind == '[' && len(terms[0].items) == 0 && len(terms) == 1 {
		// Rebar3 writes an unversioned empty list when there are no locks.
		entries = terms[0].items
	} else {
		if terms[0].kind != '{' || len(terms[0].items) != 2 || terms[0].at(0).kind != 's' || terms[0].at(1).kind != '[' {
			return model.Document{}, errors.New("rebar.lock has no dependency list")
		}
		version := terms[0].at(0).text()
		if version != "1.2.0" && version != "1.1.0" {
			return model.Document{}, fmt.Errorf("unsupported rebar.lock format %q", version)
		}
		entries = terms[0].at(1).items
	}
	doc := common.NewDocument(filename, project, "rebar", data)
	archiveHashes := collectArchiveHashes(&doc, terms[1:])
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
			component.Hashes = archiveHashes[alias]
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
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "vcs", VCSType: "git", SafeURL: clean, Revision: component.Version, Status: "declared", Evidence: evidence})
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
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "rebar_dependency_graph_unavailable"},
		model.Issue{Code: "missing_direct_dependencies"},
		model.Issue{Code: "rebar_distribution_origin_unverified"})
	common.Finalize(&doc)
	return doc, nil
}

// Only pkg_hash_ext is the distribution tarball's SHA-256. pkg_hash is
// Hex's legacy inner checksum and must not be exported as an archive hash.
func collectArchiveHashes(doc *model.Document, attrs []term) map[string][]model.Hash {
	hashes := map[string][]model.Hash{}
	blocked := map[string]bool{}
	inner := map[string]bool{}
	unrepresented := false
	for _, list := range attrs {
		if list.kind != '[' {
			unrepresented = true
			continue
		}
		for _, attr := range list.items {
			if attr.kind != '{' || len(attr.items) != 2 || attr.at(0).kind != 'a' || attr.at(1).kind != '[' || attr.at(0).text() != "pkg_hash" && attr.at(0).text() != "pkg_hash_ext" {
				unrepresented = true
				continue
			}
			for _, entry := range attr.at(1).items {
				if entry.kind != '{' || len(entry.items) != 2 || entry.at(0).kind != 'b' || entry.at(1).kind != 'b' || !packageName.MatchString(entry.at(0).text()) {
					unrepresented = true
					continue
				}
				alias := entry.at(0).text()
				if attr.at(0).text() == "pkg_hash" {
					inner[alias] = true
					continue
				}
				hash := common.HexSHA256(entry.at(1).text())
				if len(hash) == 0 || len(hashes[alias]) > 0 && hashes[alias][0] != hash[0] {
					blocked[alias] = true
					delete(hashes, alias)
					unrepresented = true
				} else if !blocked[alias] {
					hashes[alias] = hash
				}
			}
		}
	}
	for alias := range inner {
		if len(hashes[alias]) == 0 {
			unrepresented = true
		}
	}
	if unrepresented {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "rebar_package_hash_unrepresented"})
	}
	return hashes
}

func validVersion(version string) bool {
	return version != "" && len(version) <= 128 && strings.IndexFunc(version, unicode.IsControl) < 0
}
