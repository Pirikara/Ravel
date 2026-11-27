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

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/licensing"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

type classicEntry struct {
	descriptors                  []string
	version, resolved, integrity string
	deps, optional               map[string]string
	line                         int
}

type classicManifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Workspaces           json.RawMessage   `json:"workspaces"`
	Private              json.RawMessage   `json:"private"`
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
	manifestData, manifestFile, manifestErr := common.ReadLocalNodeManifest(file, ".")
	var manifest classicManifest
	if manifestErr == nil {
		doc.Sources = append(doc.Sources, manifestFile)
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			return model.Document{}, fmt.Errorf("invalid package.json: %w", err)
		}
		if manifest.Name != "" {
			doc.Root = &model.ProjectIdentity{Name: manifest.Name, Version: manifest.Version,
				Evidence: common.Evidence(filepath.Join(filepath.Dir(file), "package.json"), "yarn-manifest", "/name", manifestData), Licenses: licensing.JSONFields(manifestData, common.Evidence(filepath.Join(filepath.Dir(file), "package.json"), "yarn-manifest", "", manifestData))}
			common.CollectNodeDevelopment(&doc, "root", manifestData, common.Evidence(filepath.Join(filepath.Dir(file), "package.json"), "yarn-manifest", "", manifestData))
		}
	}
	if manifestErr != nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	}
	workspaces := collectClassicWorkspaces(&doc, file, manifest)
	type work struct {
		index                            int
		from, kind, condition, requested string
		evidence                         model.Evidence
	}
	queue := []work{}
	resolve := func(name, version string) int {
		index, ok := descriptorIndex[name+"@"+version]
		if ok && index >= 0 {
			entry := entries[index]
			if _, _, valid := classicEntryName(entry); valid && entry.version != "" {
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
	enqueue := func(from, kind, condition, name, version string, evidence model.Evidence) {
		if local, known := classicWorkspaceTarget(&doc, workspaces, name, version); local != "" {
			doc.Edges = append(doc.Edges, model.Edge{From: from, To: local, Kind: kind, Condition: condition, Evidence: evidence})
			if condition != "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: name})
			}
			return
		} else if !known {
			return
		}
		if index := resolve(name, version); index >= 0 {
			queue = append(queue, work{index: index, from: from, kind: kind, condition: condition, requested: name, evidence: evidence})
		}
	}
	seedManifest := func(from string, m classicManifest, input string, content []byte) int {
		count := 0
		for _, group := range []struct {
			name string
			deps map[string]string
		}{{"dependencies", m.Dependencies}, {"devDependencies", m.DevDependencies}, {"optionalDependencies", m.OptionalDependencies}} {
			for name, version := range group.deps {
				count++
				condition := ""
				if group.name == "optionalDependencies" {
					condition = "optional"
				}
				kind := "depends_on"
				if from == "root" {
					kind = "direct"
				}
				enqueue(from, kind, condition, name, version, common.Evidence(input, "yarn-manifest", "/"+group.name+"/"+strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1"), content))
			}
		}
		return count
	}
	rootCount := 0
	if manifestErr == nil {
		rootCount = seedManifest("root", manifest, manifestFile, manifestData)
		for _, workspace := range workspaces {
			seedManifest(workspace.ref, workspace.manifest, workspace.input, workspace.data)
		}
		if rootCount == 0 && len(workspaces) == 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
		}
	} else {
		for i, entry := range entries {
			for _, descriptor := range entry.descriptors {
				queue = append(queue, work{index: i, requested: descriptorName(descriptor)})
			}
		}
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		entry := entries[item.index]
		actualName, alias, valid := classicEntryName(entry)
		name := classicVariantName(entry, item.requested, actualName)
		base := fmt.Sprintf("%d|%s|%s", item.index, strings.Join(entry.descriptors, ","), entry.version)
		if name != actualName {
			base += "|" + name
		}
		ref := "yarn:" + common.ID(base)
		if item.from != "" {
			ev := item.evidence
			if ev.Collector == "" {
				ev = common.Evidence(file, "yarn-classic", fmt.Sprintf("/line/%d", entry.line), data)
			}
			doc.Edges = append(doc.Edges, model.Edge{From: item.from, To: ref, Kind: item.kind, Condition: item.condition, Evidence: ev})
			if item.condition != "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: "optional dependency"})
			}
		}
		if seen[ref] {
			continue
		}
		seen[ref] = true
		if !valid || entry.version == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "invalid Yarn package", Line: entry.line})
			continue
		}
		ev := common.Evidence(file, "yarn-classic", fmt.Sprintf("/line/%d", entry.line), data)
		ev.Line = entry.line
		component := model.Component{ID: ref, Kind: "package", Name: name, Version: entry.version, Hashes: common.Integrity(entry.integrity), Evidence: []model.Evidence{ev}}
		locals := classicLocalLocators(entry)
		if entry.resolved != "" {
			// A resolved artifact location takes precedence over selectors,
			// which may have been overridden by Yarn resolutions.
			locals = nil
		}
		for _, locator := range locals {
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", LocalPath: locator.path, Status: "declared", Evidence: ev})
		}
		if len(locals) == 1 && locals[0].kind == "link" && entry.resolved == "" {
			component.Kind = "application"
		}
		if len(locals) > 1 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_source", Name: name})
		}
		if name != actualName {
			component.Context = "alias-of:" + actualName
		} else if alias != "" && !classicHasMultipleNames(entry) {
			component.Context = "alias:" + alias
		}
		if len(locals) == 0 && name == actualName && common.DefaultNpmRegistry(entry.resolved) {
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
		} else if len(locals) == 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
		}
		for name, version := range entry.deps {
			enqueue(ref, "depends_on", "", name, version, ev)
		}
		for name, version := range entry.optional {
			enqueue(ref, "depends_on", "optional", name, version, ev)
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
	start := 0
	if strings.HasPrefix(descriptor, "@") {
		slash := strings.IndexByte(descriptor, '/')
		if slash < 0 {
			return ""
		}
		start = slash + 1
	}
	separator := strings.IndexByte(descriptor[start:], '@')
	if separator < 0 || start+separator == 0 {
		return ""
	}
	return descriptor[:start+separator]
}

type classicLocalLocator struct{ kind, path string }

// A link/file selector declares a local location even when the lock has no
// resolved URL. Preserve that declaration without reading or executing it.
func classicLocalLocators(entry classicEntry) []classicLocalLocator {
	seen := map[classicLocalLocator]bool{}
	var result []classicLocalLocator
	for _, descriptor := range entry.descriptors {
		selector, ok := strings.CutPrefix(descriptor, descriptorName(descriptor)+"@")
		if !ok {
			continue
		}
		kind, location, ok := strings.Cut(selector, ":")
		if !ok || kind != "link" && kind != "file" || location == "" || strings.ContainsAny(location, "\x00\r\n") {
			continue
		}
		locator := classicLocalLocator{kind, location}
		if !seen[locator] {
			result = append(result, locator)
			seen[locator] = true
		}
	}
	return result
}

func classicEntryName(entry classicEntry) (name, alias string, valid bool) {
	if len(entry.descriptors) == 0 {
		return "", "", false
	}
	name = descriptorName(entry.descriptors[0])
	if !classicName.MatchString(name) {
		return "", "", false
	}
	actual := ""
	for _, descriptor := range entry.descriptors {
		if !classicName.MatchString(descriptorName(descriptor)) {
			return "", "", false
		}
		at := strings.Index(descriptor, "@npm:")
		if at < 0 {
			continue
		}
		if at == 0 || !classicName.MatchString(descriptor[:at]) {
			return "", "", false
		}
		rawTarget := descriptor[at+len("@npm:"):]
		target := descriptorName(rawTarget)
		if target == "" && classicName.MatchString(rawTarget) {
			// A bare npm alias leaves version selection to the lock record.
			target = rawTarget
		}
		if !classicName.MatchString(target) || actual != "" && actual != target {
			return "", "", false
		}
		actual = target
	}
	if actual != "" && actual != name {
		return actual, name, true
	}
	return name, "", true
}

func classicHasMultipleNames(entry classicEntry) bool {
	if len(entry.descriptors) < 2 {
		return false
	}
	first := descriptorName(entry.descriptors[0])
	for _, descriptor := range entry.descriptors[1:] {
		if descriptorName(descriptor) != first {
			return true
		}
	}
	return false
}

func classicVariantName(entry classicEntry, requested, actual string) string {
	if !classicHasMultipleNames(entry) {
		return actual
	}
	primary := descriptorName(entry.descriptors[0])
	for _, descriptor := range entry.descriptors {
		if descriptorName(descriptor) == actual {
			primary = actual
			break
		}
	}
	if requested == primary {
		return actual
	}
	for _, descriptor := range entry.descriptors {
		if descriptorName(descriptor) == requested {
			return requested
		}
	}
	return actual
}
