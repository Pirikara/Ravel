package oci

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const (
	maxRDescriptionBytes = 1 << 20
	maxRDescriptionFiles = 5000
	maxRDescriptionTotal = 64 << 20
	maxRLibraryRoots     = 32
	maxRLibraryPathBytes = 4096
)

var rPackageName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]{0,127}$`)
var rPackageVersion = regexp.MustCompile(`^[0-9]+(?:[.-][0-9]+)*$`)
var rDependency = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9.]*)(?:\s*\(\s*(>=|<=|==|=|>|<)\s*([0-9]+(?:[.-][0-9]+)*)\s*\))?$`)

type rDescriptionField struct {
	value string
	line  int
}

type rInstalledRecord struct {
	component model.Component
	fields    map[string]rDescriptionField
}

type rLibraryRoot struct {
	dir      string
	variable string
}

// The image config supplies only literal Unix library roots. R also expands
// version tokens and can modify .libPaths() at startup; those cases are left
// unresolved rather than guessed from image contents.
func installedRLibraryRoots(env []string) ([]rLibraryRoot, []model.Issue) {
	values := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok && (key == "R_LIBS" || key == "R_LIBS_USER" || key == "R_LIBS_SITE" || key == "R_HOME") {
			values[key] = value // OCI environment variables use the last value of a repeated key.
		}
	}
	var roots []rLibraryRoot
	var issues []model.Issue
	seen := map[string]bool{}
	issueAdded := map[string]bool{}
	addIssue := func(key string) {
		if !issueAdded[key] {
			issues = append(issues, model.Issue{Code: "r_installed_library_path_unresolved", Name: key})
			issueAdded[key] = true
		}
	}
	addRoot := func(key, dir string) {
		if len(dir) > maxRLibraryPathBytes || !strings.HasPrefix(dir, "/") || dir == "/" || path.Clean(dir) != dir || strings.ContainsAny(dir, "\\\x00%~") {
			addIssue(key)
			return
		}
		if seen[dir] {
			return
		}
		if len(roots) >= maxRLibraryRoots {
			addIssue(key)
			return
		}
		roots = append(roots, rLibraryRoot{dir: strings.TrimPrefix(dir, "/"), variable: key})
		seen[dir] = true
	}
	for _, key := range []string{"R_LIBS", "R_LIBS_USER", "R_LIBS_SITE"} {
		value := values[key]
		if value == "" || value == "NULL" {
			continue
		}
		if len(value) > maxRLibraryRoots*maxRLibraryPathBytes {
			addIssue(key)
			continue
		}
		for _, dir := range strings.Split(value, ":") {
			if dir != "" {
				addRoot(key, dir)
			}
		}
	}
	if home := values["R_HOME"]; home != "" {
		if len(home) > maxRLibraryPathBytes || !strings.HasPrefix(home, "/") || home == "/" || path.Clean(home) != home || strings.ContainsAny(home, "\\\x00%~") {
			addIssue("R_HOME")
		} else {
			addRoot("R_HOME", home+"/library")
			addRoot("R_HOME", home+"/site-library")
		}
	}
	return roots, issues
}

func isConventionalRDescriptionPath(name string) bool {
	parts := strings.Split(name, "/")
	n := len(parts)
	return n >= 5 && parts[n-1] == "DESCRIPTION" && rPackageName.MatchString(parts[n-2]) &&
		(parts[n-3] == "site-library" || parts[n-3] == "library") && parts[n-4] == "R" && parts[n-5] == "lib"
}

func rDescriptionLibrarySource(name string, roots []rLibraryRoot) (string, bool) {
	if isConventionalRDescriptionPath(name) {
		return "", true
	}
	for _, root := range roots {
		remainder, found := strings.CutPrefix(name, root.dir+"/")
		if !found {
			continue
		}
		packageName, suffix, ok := strings.Cut(remainder, "/")
		if ok && suffix == "DESCRIPTION" && rPackageName.MatchString(packageName) {
			return root.variable, true
		}
	}
	return "", false
}

func isInstalledRDescriptionPath(name string, roots []rLibraryRoot) bool {
	_, found := rDescriptionLibrarySource(name, roots)
	return found
}

// Installed packages are identified from final-layer DESCRIPTION files. R's
// library() requires a Built field; source-tree DESCRIPTION files and the
// translation-only directory are therefore not treated as installed packages.
func inspectInstalledRDescription(data []byte, source, filename string, roots []rLibraryRoot) (rInstalledRecord, bool, error) {
	if len(data) == 0 || len(data) > maxRDescriptionBytes || !isInstalledRDescriptionPath(filename, roots) {
		return rInstalledRecord{}, false, errors.New("invalid R DESCRIPTION path or size")
	}
	fields, err := parseRDescriptionFields(data)
	if err != nil {
		return rInstalledRecord{}, false, err
	}
	if strings.TrimSpace(fields["Built"].value) == "" {
		return rInstalledRecord{}, false, nil
	}
	name, version := strings.TrimSpace(fields["Package"].value), strings.TrimSpace(fields["Version"].value)
	if name != path.Base(path.Dir(filename)) || !rPackageName.MatchString(name) || !rPackageVersion.MatchString(version) {
		return rInstalledRecord{}, false, errors.New("R DESCRIPTION identity conflicts with directory or has no valid version")
	}
	hash := sha256.Sum256(data)
	evidence := model.Evidence{Collector: "r-installed-description", InputPath: source, InputDigest: "sha256:" + hex.EncodeToString(hash[:]), Pointer: "Package,Version,Built", Method: "installed-description-analysis"}
	component := model.Component{
		ID:       "r-installed:" + common.ID(source+"\x00"+name+"\x00"+version),
		Kind:     "package",
		Name:     name,
		Version:  version,
		Context:  "location=/" + path.Dir(filename),
		Evidence: []model.Evidence{evidence},
	}
	return rInstalledRecord{component: component, fields: fields}, true, nil
}

func parseRDescriptionFields(data []byte) (map[string]rDescriptionField, error) {
	fields := map[string]rDescriptionField{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxRDescriptionBytes+1)
	line := 0
	previous := ""
	for scanner.Scan() {
		line++
		value := strings.TrimSuffix(scanner.Text(), "\r")
		if value == "" {
			previous = ""
			continue
		}
		if value[0] == ' ' || value[0] == '\t' {
			if previous == "" {
				return nil, fmt.Errorf("R DESCRIPTION continuation without a field at line %d", line)
			}
			field := fields[previous]
			field.value += " " + strings.TrimSpace(value)
			fields[previous] = field
			continue
		}
		key, content, ok := strings.Cut(value, ":")
		if !ok || key == "" || strings.TrimSpace(key) != key {
			return nil, fmt.Errorf("invalid R DESCRIPTION field at line %d", line)
		}
		if _, duplicate := fields[key]; duplicate && (key == "Package" || key == "Version" || key == "Built" || key == "Depends" || key == "Imports" || key == "LinkingTo") {
			return nil, fmt.Errorf("duplicate R DESCRIPTION %s field", key)
		}
		fields[key] = rDescriptionField{value: strings.TrimSpace(content), line: line}
		previous = key
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return fields, nil
}

func linkInstalledRDependencies(doc *model.Document, records []rInstalledRecord) {
	byName := map[string][]model.Component{}
	for _, record := range records {
		byName[record.component.Name] = append(byName[record.component.Name], record.component)
	}
	for _, record := range records {
		for _, key := range []string{"Depends", "Imports", "LinkingTo"} {
			field, found := record.fields[key]
			if !found || field.value == "" {
				continue
			}
			for _, item := range strings.Split(field.value, ",") {
				item = strings.TrimSpace(item)
				match := rDependency.FindStringSubmatch(item)
				if match == nil {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "r_installed_dependency_unparsed", Name: item, Scope: record.component.Name, Line: field.line})
					continue
				}
				name, op, wantVersion := match[1], match[2], match[3]
				if name == "R" {
					continue // R itself is a runtime requirement, not an installed package edge.
				}
				candidates := byName[name]
				if len(candidates) == 0 {
					if key != "LinkingTo" {
						doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "r_installed_dependency_unresolved", Name: name, Scope: record.component.Name, Line: field.line})
					}
					continue
				}
				if len(candidates) != 1 {
					if key != "LinkingTo" {
						doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "r_installed_dependency_ambiguous", Name: name, Scope: record.component.Name, Line: field.line})
					}
					continue
				}
				if op != "" {
					comparison, ok := compareRVersions(candidates[0].Version, wantVersion)
					if !ok {
						doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "r_installed_dependency_constraint_unverified", Name: name, Scope: record.component.Name, Line: field.line})
						continue
					}
					matches := op == ">=" && comparison >= 0 || op == "<=" && comparison <= 0 || (op == "=" || op == "==") && comparison == 0 || op == ">" && comparison > 0 || op == "<" && comparison < 0
					if !matches {
						if key != "LinkingTo" {
							doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "r_installed_dependency_unresolved", Name: name, Scope: record.component.Name, Line: field.line})
						}
						continue
					}
				}
				evidence := record.component.Evidence[0]
				evidence.Line = field.line
				evidence.Pointer = key
				edge := model.Edge{From: record.component.ID, To: candidates[0].ID, Kind: "depends_on", Evidence: evidence}
				if key == "LinkingTo" {
					edge.Condition = "kind=build"
				}
				doc.Edges = append(doc.Edges, edge)
			}
		}
	}
}

func compareRVersions(a, b string) (int, bool) {
	if !rPackageVersion.MatchString(a) || !rPackageVersion.MatchString(b) {
		return 0, false
	}
	partsA := strings.FieldsFunc(a, func(r rune) bool { return r == '.' || r == '-' })
	partsB := strings.FieldsFunc(b, func(r rune) bool { return r == '.' || r == '-' })
	n := len(partsA)
	if len(partsB) > n {
		n = len(partsB)
	}
	for i := 0; i < n; i++ {
		var x, y uint64
		var err error
		if i < len(partsA) {
			x, err = strconv.ParseUint(partsA[i], 10, 64)
			if err != nil {
				return 0, false
			}
		}
		if i < len(partsB) {
			y, err = strconv.ParseUint(partsB[i], 10, 64)
			if err != nil {
				return 0, false
			}
		}
		if x < y {
			return -1, true
		}
		if x > y {
			return 1, true
		}
	}
	return 0, true
}
