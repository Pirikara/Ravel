package gomod

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

type vendorModule struct {
	path               string
	version            string
	replacement        string
	replacementVersion string
	explicit           bool
	packages           int
	line               int
}

func CollectVendor(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	if filepath.Base(file) != "modules.txt" || filepath.Base(filepath.Dir(file)) != "vendor" {
		return model.Document{}, fmt.Errorf("Go vendor input must be vendor/modules.txt")
	}
	vendorDir := filepath.Dir(file)
	projectDir := filepath.Dir(vendorDir)
	modules, issues, err := parseVendor(data, vendorDir)
	if err != nil {
		return model.Document{}, err
	}
	doc := common.NewDocument(file, project, "go", data)
	doc.Coverage.Issues = append(doc.Coverage.Issues, issues...)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "transitive_graph_unavailable"})
	byPath := map[string]vendorModule{}
	allHeaders := map[string]vendorModule{}
	for _, entry := range modules {
		allHeaders[entry.path+"@"+entry.version] = entry
		if entry.packages == 0 {
			continue
		}
		if previous, exists := byPath[entry.path]; exists {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: entry.path})
			if previous.version != entry.version {
				continue
			}
		}
		byPath[entry.path] = entry
	}
	var paths []string
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	refs := map[string]string{}
	for _, path := range paths {
		entry := byPath[path]
		ref := "go:" + common.ID(entry.path+"|"+entry.version+"|"+entry.replacement+"|"+entry.replacementVersion)
		refs[path] = ref
		ev := common.Evidence(file, "go-vendor", fmt.Sprintf("/line/%d", entry.line), data)
		ev.Line = entry.line
		identity := ""
		if entry.replacement == "" {
			identity = common.GoModulePURL(entry.path, entry.version)
		}
		doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: entry.path, Version: entry.version, PURL: identity, Evidence: []model.Evidence{ev}})
		switch {
		case entry.replacement == "":
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: entry.path})
		case entry.replacementVersion == "":
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
		case module.CheckPath(entry.replacement) == nil && semver.IsValid(entry.replacementVersion):
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "module_replacement", Target: entry.replacement + "@" + entry.replacementVersion, Status: "declared", Evidence: ev})
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "source_unresolved", Name: entry.path})
		default:
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: entry.path})
		}
	}
	if _, err := os.Stat(filepath.Join(projectDir, "go.work")); err == nil {
		doc.Sources = append(doc.Sources, filepath.Join(projectDir, "go.work"))
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "workspace_unresolved"})
	} else {
		modPath := filepath.Join(projectDir, "go.mod")
		modData, err := os.ReadFile(modPath)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
		} else {
			doc.Sources = append(doc.Sources, modPath)
			mod, err := modfile.Parse(modPath, modData, nil)
			if err != nil {
				return model.Document{}, fmt.Errorf("invalid go.mod: %w", err)
			}
			mainRef, err := addMainModule(&doc, mod, modPath, modData)
			if err != nil {
				return model.Document{}, err
			}
			requireExplicit := mod.Go == nil || semver.Compare("v"+mod.Go.Version, "v1.14.0") >= 0
			for _, req := range mod.Require {
				header, headerFound := allHeaders[req.Mod.Path+"@"+req.Mod.Version]
				if requireExplicit && (!headerFound || !header.explicit) {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "vendor_manifest_mismatch", Name: req.Mod.Path})
					continue
				}
				if headerFound && !replacementMatches(mod, header) {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "vendor_manifest_mismatch", Name: req.Mod.Path})
					continue
				}
				entry, found := byPath[req.Mod.Path]
				if !found {
					continue
				}
				if req.Mod.Version != entry.version {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "vendor_manifest_mismatch", Name: req.Mod.Path})
					continue
				}
				if req.Indirect {
					continue
				}
				doc.Edges = append(doc.Edges, model.Edge{From: mainRef, To: refs[req.Mod.Path], Kind: "direct", Evidence: common.Evidence(modPath, "go-manifest", "/require/"+common.ID(req.Mod.Path), modData)})
			}
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func parseVendor(data []byte, vendorDir string) ([]vendorModule, []model.Issue, error) {
	var result []vendorModule
	var issues []model.Issue
	index := map[string]int{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	current := -1
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "# "):
			fields := strings.Fields(line)
			if len(fields) < 3 || module.CheckPath(fields[1]) != nil {
				return nil, nil, fmt.Errorf("invalid vendor/modules.txt header at line %d", lineNumber)
			}
			if fields[2] == "=>" {
				current = -1
				continue
			}
			if !semver.IsValid(fields[2]) {
				return nil, nil, fmt.Errorf("invalid vendor module version at line %d", lineNumber)
			}
			key := fields[1] + "@" + fields[2]
			position, ok := index[key]
			if !ok {
				position = len(result)
				index[key] = position
				result = append(result, vendorModule{path: fields[1], version: fields[2], line: lineNumber})
			}
			current = position
			if len(fields) > 3 {
				if len(fields) != 5 && len(fields) != 6 || fields[3] != "=>" {
					return nil, nil, fmt.Errorf("invalid vendor replacement at line %d", lineNumber)
				}
				result[current].replacement = fields[4]
				if len(fields) == 6 {
					result[current].replacementVersion = fields[5]
				}
			}
		case strings.HasPrefix(line, "## "):
			if current < 0 {
				return nil, nil, fmt.Errorf("orphan vendor annotation at line %d", lineNumber)
			}
			for _, annotation := range strings.Split(strings.TrimPrefix(line, "## "), ";") {
				if strings.TrimSpace(annotation) == "explicit" {
					result[current].explicit = true
				}
			}
		case strings.HasPrefix(line, "#"):
			return nil, nil, fmt.Errorf("unknown vendor header at line %d", lineNumber)
		default:
			if current < 0 || module.CheckImportPath(line) != nil || !(line == result[current].path || strings.HasPrefix(line, result[current].path+"/")) {
				return nil, nil, fmt.Errorf("invalid vendored package at line %d", lineNumber)
			}
			packageDir := filepath.Join(vendorDir, filepath.FromSlash(line))
			if info, err := os.Lstat(packageDir); err != nil || !info.IsDir() {
				issues = append(issues, model.Issue{Code: "vendor_package_missing", Name: line, Line: lineNumber})
				continue
			}
			result[current].packages++
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("reading vendor/modules.txt: %w", err)
	}
	return result, issues, nil
}

func replacementMatches(mod *modfile.File, entry vendorModule) bool {
	var replacement *modfile.Replace
	for _, candidate := range mod.Replace {
		if candidate.Old.Path == entry.path && candidate.Old.Version == "" {
			replacement = candidate
		}
	}
	for _, candidate := range mod.Replace {
		if candidate.Old.Path == entry.path && candidate.Old.Version == entry.version {
			replacement = candidate
		}
	}
	if replacement == nil {
		return entry.replacement == ""
	}
	if replacement.New.Version != entry.replacementVersion {
		return false
	}
	if replacement.New.Version == "" {
		return filepath.Clean(replacement.New.Path) == filepath.Clean(entry.replacement)
	}
	return replacement.New.Path == entry.replacement
}
