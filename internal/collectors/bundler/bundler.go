package bundler

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

var specLine = regexp.MustCompile(`^ {4}([^ ()]+) \(([^()]+)\)$`)
var revisionPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

type block struct {
	kind     string
	remotes  []remote
	revision string
}

type remote struct {
	value string
	line  int
}

type dependency struct {
	name string
	line int
}

type entry struct {
	component model.Component
	block     *block
	deps      []dependency
}

// Collect reads one Gemfile.lock without executing Bundler or contacting a registry.
func Collect(path, project string) (model.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.Document{}, err
	}
	digest := sha256.Sum256(data)
	digestText := "sha256:" + hex.EncodeToString(digest[:])
	evidence := func(line int) model.Evidence {
		return model.Evidence{Collector: "bundler-lock", InputPath: path, InputDigest: digestText, Line: line, Method: "lockfile-analysis"}
	}
	doc := model.Document{
		SchemaVersion: "0.1", Project: project, Source: path,
		Components: []model.Component{}, Edges: []model.Edge{}, Origins: []model.Origin{},
		Coverage: model.Coverage{Manager: "bundler", GraphState: "complete_for_scope", OriginState: "complete_for_scope", Issues: []model.Issue{}},
	}
	var entries []*entry
	var direct []dependency
	var platforms []string
	var current *block
	var owner *entry
	section := ""
	inSpecs := false
	blockNumber := 0
	occurrenceCount := map[string]int{}
	foundDirectSection := false
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 8*1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		if line[0] != ' ' {
			section = strings.TrimSpace(line)
			owner = nil
			inSpecs = false
			current = nil
			if section == "DEPENDENCIES" {
				foundDirectSection = true
			}
			switch section {
			case "GEM", "GIT", "PATH", "PLUGIN SOURCE":
				blockNumber++
				current = &block{kind: section}
			}
			continue
		}
		if current != nil {
			if strings.HasPrefix(line, "  revision: ") {
				candidate := strings.TrimSpace(strings.TrimPrefix(line, "  revision: "))
				if revisionPattern.MatchString(candidate) {
					current.revision = candidate
				}
				continue
			}
			if strings.HasPrefix(line, "  remote: ") {
				current.remotes = append(current.remotes, remote{value: strings.TrimSpace(strings.TrimPrefix(line, "  remote: ")), line: lineNumber})
				continue
			}
			if line == "  specs:" {
				inSpecs = true
				continue
			}
			if !inSpecs {
				continue
			}
			if m := specLine.FindStringSubmatch(line); m != nil {
				name, version := m[1], m[2]
				key := fmt.Sprintf("%d:%s:%s", blockNumber, name, version)
				ordinal := occurrenceCount[key]
				occurrenceCount[key]++
				if ordinal > 0 {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "duplicate_spec", Name: name, Line: lineNumber})
				}
				seed := fmt.Sprintf("%s:%d", key, ordinal)
				idHash := sha256.Sum256([]byte(seed))
				id := "gem:" + hex.EncodeToString(idHash[:12])
				purl := "pkg:gem/" + url.PathEscape(name) + "@" + common.PURLVersion(version)
				owner = &entry{component: model.Component{
					ID: id, Kind: "package", Name: name, Version: version, PURL: purl,
					Evidence: []model.Evidence{evidence(lineNumber)},
				}, block: current, deps: []dependency{}}
				entries = append(entries, owner)
				continue
			}
			if strings.HasPrefix(line, "      ") && !strings.HasPrefix(line, "       ") && owner != nil {
				parts := strings.Fields(strings.TrimSpace(line))
				if len(parts) > 0 {
					owner.deps = append(owner.deps, dependency{name: strings.TrimSuffix(parts[0], "!"), line: lineNumber})
				}
			}
			continue
		}
		if section == "DEPENDENCIES" && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			parts := strings.Fields(strings.TrimSpace(line))
			if len(parts) > 0 {
				direct = append(direct, dependency{name: strings.TrimSuffix(parts[0], "!"), line: lineNumber})
			}
		}
		if section == "PLATFORMS" && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			platforms = append(platforms, strings.TrimSpace(line))
		}
	}
	if err := scanner.Err(); err != nil {
		return model.Document{}, err
	}
	if len(entries) == 0 {
		return model.Document{}, fmt.Errorf("no Bundler packages found in %s", filepath.Base(path))
	}
	doc.Coverage.Platforms = platforms
	for _, item := range entries {
		for _, platform := range platforms {
			if strings.HasSuffix(item.component.Version, "-"+platform) {
				item.component.Version = strings.TrimSuffix(item.component.Version, "-"+platform)
				item.component.Platform = platform
				item.component.PURL = "pkg:gem/" + url.PathEscape(item.component.Name) + "@" + common.PURLVersion(item.component.Version) + "?platform=" + url.QueryEscape(platform)
				break
			}
		}
	}
	byName := map[string][]*entry{}
	for _, item := range entries {
		if item.block.kind != "GEM" || len(item.block.remotes) != 1 || !defaultRubyGemsRemote(item.block.remotes[0].value) {
			item.component.PURL = ""
		}
		doc.Components = append(doc.Components, item.component)
		byName[item.component.Name] = append(byName[item.component.Name], item)
		if len(item.block.remotes) > 1 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_source", Name: item.component.Name, Line: item.component.Evidence[0].Line})
			continue
		}
		if len(item.block.remotes) == 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: item.component.Name, Line: item.component.Evidence[0].Line})
			continue
		}
		r := item.block.remotes[0]
		origin := model.Origin{Occurrence: item.component.ID, Evidence: evidence(r.line), Status: "declared", Revision: item.block.revision}
		switch item.block.kind {
		case "GEM":
			origin.Kind = "declared_registry"
			origin.SafeURL = safeurl.Clean(r.value)
		case "GIT":
			origin.Kind = "vcs"
			origin.SafeURL = safeurl.Clean(r.value)
		case "PATH":
			origin.Kind = "local"
			if !filepath.IsAbs(r.value) {
				origin.LocalPath = filepath.Clean(r.value)
			}
		default:
			origin.Kind = "configured_repository"
			origin.SafeURL = safeurl.Clean(r.value)
		}
		if origin.Kind != "local" && origin.SafeURL == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: item.component.Name, Line: r.line})
			continue
		}
		doc.Origins = append(doc.Origins, origin)
	}
	resolve := func(dep dependency) string {
		matches := byName[dep.name]
		switch len(matches) {
		case 1:
			return matches[0].component.ID
		case 0:
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: dep.name, Line: dep.line})
		default:
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: dep.name, Line: dep.line})
		}
		return ""
	}
	seen := map[string]bool{}
	addEdge := func(from, to, kind string, line int) {
		key := from + "\x00" + to + "\x00" + kind
		if seen[key] {
			return
		}
		seen[key] = true
		doc.Edges = append(doc.Edges, model.Edge{From: from, To: to, Kind: kind, Evidence: evidence(line)})
	}
	for _, item := range entries {
		for _, dep := range item.deps {
			if id := resolve(dep); id != "" {
				addEdge(item.component.ID, id, "depends_on", dep.line)
			}
		}
	}
	for _, dep := range direct {
		if id := resolve(dep); id != "" {
			addEdge("root", id, "direct", dep.line)
		}
	}
	if len(platforms) > 1 {
		for i := range doc.Edges {
			doc.Edges[i].Condition = "platform=unspecified"
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "multiple_platforms"})
	}
	if !foundDirectSection {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	}
	for _, issue := range doc.Coverage.Issues {
		switch issue.Code {
		case "unresolved_dependency", "ambiguous_dependency", "missing_direct_dependencies", "duplicate_spec", "multiple_platforms":
			doc.Coverage.GraphState = "partial"
		default:
			doc.Coverage.OriginState = "partial"
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func defaultRubyGemsRemote(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && strings.EqualFold(u.Hostname(), "rubygems.org") && (u.Port() == "" || u.Port() == "443") && (u.Path == "" || u.Path == "/")
}
