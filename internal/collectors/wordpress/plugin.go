package wordpress

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

// WordPress reads plugin headers from the first 8 KiB, even in larger files.
const HeaderBytes = 8 << 10
const MaxFiles = 5000

var dependencySlug = regexp.MustCompile("^[a-z0-9]+(-[a-z0-9]+)*$")

type Record struct {
	Component model.Component
	Group     string
	Slug      string
	required  string
	depEv     model.Evidence
}

// InstalledPath recognizes the normal plugin slots, including loose PHP files
// and top-level MU plugins. Deeper PHP files are implementation details.
func InstalledPath(filename string) (group, slug, kind string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(filename, "/"), "/")
	for i := len(parts) - 3; i >= 0; i-- {
		if parts[i] != "wp-content" || parts[i+1] != "plugins" && parts[i+1] != "mu-plugins" {
			continue
		}
		rest := parts[i+2:]
		if len(rest) != 1 && (len(rest) != 2 || parts[i+1] == "mu-plugins") {
			return "", "", "", false
		}
		for _, part := range rest {
			if part == "" || strings.HasPrefix(part, ".") {
				return "", "", "", false
			}
		}
		if !strings.HasSuffix(rest[len(rest)-1], ".php") {
			return "", "", "", false
		}
		slug = rest[0]
		if len(rest) == 1 {
			slug = strings.TrimSuffix(slug, ".php")
		}
		return strings.Join(parts[:i+2], "/"), slug, parts[i+1], true
	}
	return "", "", "", false
}

// Parse inspects data only; PHP and WordPress are never executed. InputDigest
// covers the header prefix, as identified by the evidence method and pointer.
func Parse(data []byte, source, location string) (Record, bool, error) {
	if len(data) > HeaderBytes {
		data = data[:HeaderBytes]
	}
	fields := map[string]string{}
	lines := map[string]int{}
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimLeft(line, " \t")
		if strings.HasPrefix(line, "<?") {
			line = line[2:]
			if len(line) >= 3 && strings.EqualFold(line[:3], "php") {
				line = line[3:]
			}
		}
		line = strings.TrimLeft(line, " \t/*#@")
		key, value, ok := strings.Cut(line, ":")
		key = strings.ToLower(key)
		if !ok || key != "plugin name" && key != "version" && key != "requires plugins" {
			continue
		}
		if _, exists := fields[key]; exists {
			continue
		}
		for _, ending := range []string{"*/", "?>"} {
			if before, _, found := strings.Cut(value, ending); found {
				value = before
			}
		}
		fields[key], lines[key] = strings.TrimSpace(value), i+1
	}
	name := fields["plugin name"]
	if name == "" {
		return Record{}, false, nil
	}
	if !validField(name, 512) || !validField(fields["version"], 128) {
		return Record{}, true, errors.New("invalid WordPress plugin identity")
	}
	group, slug, kind, installed := InstalledPath(filepath.ToSlash(location))
	if !installed {
		kind = "source"
		slug = strings.TrimSuffix(path.Base(filepath.ToSlash(location)), ".php")
	}
	ev := common.Evidence(source, "wordpress-plugin-header", fmt.Sprintf("bytes/0:%d/header/Plugin Name", len(data)), data)
	ev.Method, ev.Line = "header-prefix-analysis", lines["plugin name"]
	component := model.Component{
		ID: "wordpress:" + common.ID(location), Kind: "package", Name: name, Version: fields["version"],
		Context:  "ecosystem=wordpress-plugin;kind=" + kind + ";slug=" + slug + ";location=" + location,
		Evidence: []model.Evidence{ev},
	}
	if lines["version"] != 0 {
		versionEv := ev
		versionEv.Line, versionEv.Pointer = lines["version"], fmt.Sprintf("bytes/0:%d/header/Version", len(data))
		component.Evidence = append(component.Evidence, versionEv)
	}
	depEv := ev
	depEv.Line, depEv.Pointer = lines["requires plugins"], fmt.Sprintf("bytes/0:%d/header/Requires Plugins", len(data))
	return Record{Component: component, Group: group, Slug: slug, required: fields["requires plugins"], depEv: depEv}, true, nil
}

func validField(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

// Append links declarations only within one observed plugins directory. Source
// checkouts and MU plugins do not establish activation of normal plugins.
func Append(doc *model.Document, records []Record) {
	bySlug := map[string][]Record{}
	for _, record := range records {
		if record.Group != "" && path.Base(record.Group) == "plugins" {
			key := record.Group + "\x00" + record.Slug
			bySlug[key] = append(bySlug[key], record)
		}
		doc.Components = append(doc.Components, record.Component)
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: record.Component.ID, Kind: "observed", Evidence: record.Component.Evidence[0]})
		if record.Component.Version == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "version_unresolved", Name: record.Component.Name})
		}
	}
	for _, record := range records {
		seen := map[string]bool{}
		for _, slug := range strings.Split(record.required, ",") {
			slug = strings.TrimSpace(slug)
			if slug == "" || seen[slug] {
				continue
			}
			seen[slug] = true
			candidates := bySlug[record.Group+"\x00"+slug]
			if !dependencySlug.MatchString(slug) || len(slug) > 200 || record.Group == "" || len(candidates) != 1 || candidates[0].Component.ID == record.Component.ID {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "wordpress_plugin_dependency_unresolved", Name: record.Component.Name, Scope: record.depEv.InputPath})
				continue
			}
			doc.Edges = append(doc.Edges, model.Edge{From: record.Component.ID, To: candidates[0].Component.ID, Kind: "depends_on", Condition: "activation=unverified", Evidence: record.depEv})
		}
	}
	if len(records) > 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "wordpress_plugin_activation_unverified"}, model.Issue{Code: "wordpress_plugin_origin_unavailable"})
	}
}

func readPrefix(file string) ([]byte, error) {
	info, err := os.Lstat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("WordPress plugin input must be a regular file")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, HeaderBytes))
}

// Files finds header-bearing PHP files directly inside a directory. Recursive
// traversal is owned by the CLI, with its standard exclusions and entry budget.
func Files(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var files []string
	candidates := 0
	for _, entry := range entries {
		if !entry.Type().IsRegular() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(entry.Name(), ".php") {
			continue
		}
		candidates++
		if candidates > MaxFiles {
			return nil, errors.New("too many WordPress plugin candidates")
		}
		file := filepath.Join(directory, entry.Name())
		location := filepath.ToSlash(file)
		if strings.Contains("/"+location, "/wp-content/plugins/") || strings.Contains("/"+location, "/wp-content/mu-plugins/") {
			if _, _, _, ok := InstalledPath(location); !ok {
				continue
			}
		}
		data, err := readPrefix(file)
		if err != nil {
			return nil, err
		}
		_, found, err := Parse(data, file, filepath.ToSlash(file))
		if err != nil {
			return nil, err
		}
		if found {
			files = append(files, file)
		}
	}
	return files, nil
}

func Collect(input, project string) (model.Document, error) {
	files := []string{input}
	info, err := os.Stat(input)
	if err != nil {
		return model.Document{}, err
	}
	if info.IsDir() {
		files, err = Files(input)
		if err != nil {
			return model.Document{}, err
		}
	}
	return CollectFiles(files, project)
}

func CollectFiles(files []string, project string) (model.Document, error) {
	if len(files) == 0 || len(files) > MaxFiles {
		return model.Document{}, errors.New("no WordPress plugin headers or too many inputs")
	}
	files = append([]string(nil), files...)
	sort.Strings(files)
	doc := common.NewDocument(files[0], project, "wordpress", nil)
	var records []Record
	for _, file := range files {
		data, err := readPrefix(file)
		if err != nil {
			return model.Document{}, err
		}
		record, found, err := Parse(data, file, filepath.ToSlash(file))
		if err != nil {
			return model.Document{}, err
		}
		if !found {
			return model.Document{}, fmt.Errorf("no WordPress plugin header in %s", file)
		}
		records = append(records, record)
		doc.Sources = append(doc.Sources, file)
	}
	Append(&doc, records)
	common.Finalize(&doc)
	return doc, nil
}
