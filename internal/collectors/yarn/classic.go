package yarn

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

type classicEntry struct {
	descriptors                  []string
	version, resolved, integrity string
	deps, optional               map[string]string
	line                         int
}

type classicManifest struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Workspaces           json.RawMessage   `json:"workspaces"`
}

var classicName = regexp.MustCompile(`^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+$`)

func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	if bytes.Contains(data, []byte("\n__metadata:")) || bytes.HasPrefix(data, []byte("__metadata:")) {
		return collectBerry(file, project, data)
	}
	if !bytes.Contains(data, []byte("# yarn lockfile v1")) {
		return model.Document{}, fmt.Errorf("unsupported Yarn lockfile format")
	}
	return collectClassic(file, project, data)
}

func collectClassic(file, project string, data []byte) (model.Document, error) {
	entries, err := parseClassic(data)
	if err != nil {
		return model.Document{}, err
	}
	doc := common.NewDocument(file, project, "yarn", data)
	descriptorIndex := map[string]int{}
	for i, entry := range entries {
		for _, descriptor := range entry.descriptors {
			if prior, exists := descriptorIndex[descriptor]; exists && prior != i {
				descriptorIndex[descriptor] = -1
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "duplicate_spec", Name: "Yarn descriptor", Line: entry.line})
			} else if !exists {
				descriptorIndex[descriptor] = i
			}
		}
	}
	manifestData, manifestErr := os.ReadFile(filepath.Join(filepath.Dir(file), "package.json"))
	var manifest classicManifest
	if manifestErr == nil {
		doc.Sources = append(doc.Sources, filepath.Join(filepath.Dir(file), "package.json"))
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			return model.Document{}, fmt.Errorf("invalid package.json: %w", err)
		}
	}
	if manifestErr != nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	}
	if len(manifest.Workspaces) > 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unreachable_graph", Name: "Yarn workspaces"})
	}
	type work struct {
		index                 int
		from, kind, condition string
	}
	queue := []work{}
	resolve := func(name, version string) int {
		index, ok := descriptorIndex[name+"@"+version]
		if ok && index >= 0 {
			entry := entries[index]
			if classicName.MatchString(descriptorName(entry.descriptors[0])) && entry.version != "" {
				return index
			}
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "invalid Yarn package"})
			return -1
		}
		code := "unresolved_dependency"
		if ok {
			code = "ambiguous_dependency"
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name})
		return -1
	}
	rootCount := 0
	if manifestErr == nil {
		for _, group := range []map[string]string{manifest.Dependencies, manifest.DevDependencies} {
			for name, version := range group {
				rootCount++
				if index := resolve(name, version); index >= 0 {
					queue = append(queue, work{index: index, from: "root", kind: "direct"})
				}
			}
		}
		for name, version := range manifest.OptionalDependencies {
			rootCount++
			if index := resolve(name, version); index >= 0 {
				queue = append(queue, work{index: index, from: "root", kind: "direct", condition: "optional"})
			}
		}
		if rootCount == 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
		}
	} else {
		for i := range entries {
			queue = append(queue, work{index: i})
		}
	}
	seen := map[int]bool{}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		entry := entries[item.index]
		ref := "yarn:" + common.ID(fmt.Sprintf("%d|%s|%s", item.index, strings.Join(entry.descriptors, ","), entry.version))
		if item.from != "" {
			ev := common.Evidence(file, "yarn-classic", fmt.Sprintf("/line/%d", entry.line), data)
			if item.from == "root" && manifestErr == nil {
				ev = common.Evidence(filepath.Join(filepath.Dir(file), "package.json"), "yarn-manifest", "/dependencies", manifestData)
			}
			doc.Edges = append(doc.Edges, model.Edge{From: item.from, To: ref, Kind: item.kind, Condition: item.condition, Evidence: ev})
			if item.condition != "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: "optional dependency"})
			}
		}
		if seen[item.index] {
			continue
		}
		seen[item.index] = true
		name := descriptorName(entry.descriptors[0])
		if !classicName.MatchString(name) || entry.version == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "invalid Yarn package", Line: entry.line})
			continue
		}
		ev := common.Evidence(file, "yarn-classic", fmt.Sprintf("/line/%d", entry.line), data)
		ev.Line = entry.line
		component := model.Component{ID: ref, Kind: "package", Name: name, Version: entry.version, Hashes: common.Integrity(entry.integrity), Evidence: []model.Evidence{ev}}
		if common.DefaultNpmRegistry(entry.resolved) {
			component.PURL = common.NpmPURL(name, entry.version)
		}
		doc.Components = append(doc.Components, component)
		if entry.resolved != "" {
			raw := strings.TrimPrefix(entry.resolved, "git+")
			clean := safeurl.Clean(raw)
			if clean == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: name})
			} else {
				kind := "download_url"
				if strings.HasPrefix(entry.resolved, "git+") || strings.HasPrefix(entry.resolved, "git://") {
					kind = "vcs"
				}
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: kind, SafeURL: clean, Status: "declared", Evidence: ev})
			}
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
		}
		for name, version := range entry.deps {
			if index := resolve(name, version); index >= 0 {
				queue = append(queue, work{index: index, from: ref, kind: "depends_on"})
			}
		}
		for name, version := range entry.optional {
			if index := resolve(name, version); index >= 0 {
				queue = append(queue, work{index: index, from: ref, kind: "depends_on", condition: "optional"})
			}
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func parseClassic(data []byte) ([]classicEntry, error) {
	entries := []classicEntry{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	section := ""
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if strings.TrimSpace(text) == "" || strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		if !strings.HasPrefix(text, " ") && strings.HasSuffix(text, ":") {
			header := strings.TrimSuffix(text, ":")
			descriptors := splitDescriptors(header)
			if len(descriptors) == 0 {
				return nil, fmt.Errorf("invalid Yarn descriptor at line %d", line)
			}
			entries = append(entries, classicEntry{descriptors: descriptors, deps: map[string]string{}, optional: map[string]string{}, line: line})
			section = ""
			continue
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("unexpected Yarn field at line %d", line)
		}
		entry := &entries[len(entries)-1]
		if strings.HasPrefix(text, "  ") && !strings.HasPrefix(text, "    ") {
			field := strings.TrimSpace(text)
			if strings.HasSuffix(field, ":") {
				section = strings.TrimSuffix(field, ":")
				continue
			}
			key, value := parseField(field)
			section = ""
			switch key {
			case "version":
				entry.version = value
			case "resolved":
				entry.resolved = value
			case "integrity":
				entry.integrity = value
			}
			continue
		}
		if strings.HasPrefix(text, "    ") {
			name, version := parseField(strings.TrimSpace(text))
			switch section {
			case "dependencies":
				entry.deps[name] = version
			case "optionalDependencies":
				entry.optional[name] = version
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func splitDescriptors(header string) []string {
	parts := []string{}
	start := 0
	quoted := false
	escaped := false
	for i, r := range header {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && quoted {
			escaped = true
			continue
		}
		if r == '"' {
			quoted = !quoted
			continue
		}
		if r == ',' && !quoted {
			part := strings.TrimSpace(header[start:i])
			if strings.HasPrefix(part, "\"") {
				unquoted, err := strconv.Unquote(part)
				if err == nil {
					part = unquoted
				}
			}
			if part != "" {
				parts = append(parts, part)
			}
			start = i + 1
		}
	}
	part := strings.TrimSpace(header[start:])
	if strings.HasPrefix(part, "\"") {
		unquoted, err := strconv.Unquote(part)
		if err == nil {
			part = unquoted
		}
	}
	if part != "" {
		parts = append(parts, part)
	}
	return parts
}

func parseField(line string) (string, string) {
	space := strings.IndexAny(line, " \t")
	if space < 0 {
		return strings.Trim(line, `"`), ""
	}
	key := strings.Trim(line[:space], `"`)
	value := strings.TrimSpace(line[space:])
	if strings.HasPrefix(value, "\"") {
		if decoded, err := strconv.Unquote(value); err == nil {
			value = decoded
		}
	}
	return key, value
}

func descriptorName(descriptor string) string {
	at := strings.LastIndexByte(descriptor, '@')
	if at <= 0 {
		return ""
	}
	return descriptor[:at]
}
