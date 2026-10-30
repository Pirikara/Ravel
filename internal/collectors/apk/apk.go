package apk

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const maxInstalledBytes = 128 << 20

var (
	packageName  = regexp.MustCompile(`^[.a-zA-Z0-9][a-zA-Z0-9._+-]*$`)
	architecture = regexp.MustCompile(`^[a-zA-Z0-9_+-]+$`)
	depName      = regexp.MustCompile(`^[a-zA-Z0-9._+:/\[\],-]+$`)
)

type installedPackage struct {
	name, version, arch string
	depends, provides   string
	broken              bool
	line, dependsLine   int
	ref                 string
}

type provider struct {
	index   int
	version string
}

type dependency struct {
	name, op, version string
}

// Collect reads the text (v2) APK installed database from a filesystem tree.
// A database alone does not establish its distribution or repository origin.
func Collect(file, project string) (model.Document, error) {
	f, err := os.Open(file)
	if err != nil {
		return model.Document{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxInstalledBytes+1))
	if err != nil {
		return model.Document{}, err
	}
	return CollectBytes(data, file, project)
}

// CollectBytes parses a verified database from a container layer. source
// identifies the bytes used as evidence, rather than a temporary host file.
func CollectBytes(data []byte, source, project string) (model.Document, error) {
	if len(data) > maxInstalledBytes {
		return model.Document{}, errors.New("APK installed database exceeded size limit")
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return model.Document{}, errors.New("binary APK installed databases are not yet supported")
	}
	packages, err := parseInstalled(data)
	if err != nil {
		return model.Document{}, err
	}
	hash := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	evidence := func(line int) model.Evidence {
		return model.Evidence{Collector: "apk-installed", InputPath: source, InputDigest: digest, Line: line, Method: "installed-database"}
	}
	doc := common.NewDocument(source, project, "apk", nil)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: "APK installed database"})
	byName := map[string][]int{}
	providers := map[string][]provider{}
	seen := map[string]bool{}
	for i := range packages {
		p := &packages[i]
		key := p.name + "\x00" + p.arch
		if seen[key] {
			return model.Document{}, fmt.Errorf("duplicate installed APK package %s:%s", p.name, p.arch)
		}
		seen[key] = true
		p.ref = "apk:" + common.ID(key+"\x00"+p.version)
		doc.Components = append(doc.Components, model.Component{ID: p.ref, Kind: "package", Name: p.name, Version: p.version, Platform: p.arch, Context: "status=installed", Evidence: []model.Evidence{evidence(p.line)}})
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: p.ref, Kind: "installed", Evidence: evidence(p.line)})
		byName[p.name] = append(byName[p.name], i)
		if p.broken {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "apk_package_unhealthy", Name: p.name, Line: p.line})
		}
	}
	for i, p := range packages {
		for _, raw := range strings.Fields(p.provides) {
			provided, ok := parseDependency(raw)
			if !ok || provided.op != "" && provided.op != "=" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "apk_dependency_unparsed", Name: raw, Scope: p.name + " provides"})
				continue
			}
			providers[provided.name] = append(providers[provided.name], provider{index: i, version: provided.version})
		}
	}
	seenEdges := map[string]bool{}
	for _, p := range packages {
		for _, raw := range strings.Fields(p.depends) {
			if strings.HasPrefix(raw, "!") { // APK conflicts are not dependency edges.
				continue
			}
			dep, ok := parseDependency(raw)
			if !ok {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "apk_dependency_unparsed", Name: raw, Line: p.dependsLine, Scope: p.name})
				continue
			}
			matches := map[string]bool{}
			unverified := false
			consider := func(ref, version string) {
				matched, verified := matchesVersion(dep.op, version, dep.version)
				if !verified {
					unverified = true
				}
				if matched {
					matches[ref] = true
				}
			}
			for _, candidate := range byName[dep.name] {
				q := packages[candidate]
				consider(q.ref, q.version)
			}
			for _, provided := range providers[dep.name] {
				consider(packages[provided.index].ref, provided.version)
			}
			if unverified {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dependency_constraint_unverified", Name: raw, Line: p.dependsLine, Scope: p.name})
			}
			if len(matches) == 0 {
				if !unverified {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: raw, Line: p.dependsLine, Scope: p.name})
				}
				continue
			}
			condition := ""
			if len(matches) > 1 || unverified {
				if len(matches) > 1 {
					condition = "provider=" + dep.name
				} else {
					condition = "constraint=" + raw
				}
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: raw, Line: p.dependsLine, Scope: p.name})
			}
			for target := range matches {
				key := p.ref + "\x00" + target + "\x00" + condition
				if seenEdges[key] {
					continue
				}
				seenEdges[key] = true
				doc.Edges = append(doc.Edges, model.Edge{From: p.ref, To: target, Kind: "depends_on", Condition: condition, Evidence: evidence(p.dependsLine)})
			}
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func parseInstalled(data []byte) ([]installedPackage, error) {
	var packages []installedPackage
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	current := installedPackage{}
	seen := map[byte]bool{}
	active := false
	line := 0
	finish := func() error {
		if !active {
			return nil
		}
		if !packageName.MatchString(current.name) || current.version == "" || strings.ContainsAny(current.version, " \t\r\n") || !architecture.MatchString(current.arch) {
			return fmt.Errorf("invalid APK installed package near line %d", current.line)
		}
		packages = append(packages, current)
		current = installedPackage{}
		seen = map[byte]bool{}
		active = false
		return nil
	}
	for scanner.Scan() {
		line++
		text := strings.TrimSuffix(scanner.Text(), "\r")
		if text == "" {
			if err := finish(); err != nil {
				return nil, err
			}
			continue
		}
		if len(text) < 2 || text[1] != ':' {
			return nil, fmt.Errorf("invalid APK installed database line %d", line)
		}
		active = true
		field, value := text[0], text[2:]
		switch field {
		case 'P', 'V', 'A':
			if seen[field] {
				return nil, fmt.Errorf("duplicate APK field %c at line %d", field, line)
			}
			seen[field] = true
			switch field {
			case 'P':
				current.name, current.line = value, line
			case 'V':
				current.version = value
			case 'A':
				current.arch = value
			}
		case 'D':
			current.depends += " " + value
			if current.dependsLine == 0 {
				current.dependsLine = line
			}
		case 'p':
			current.provides += " " + value
		case 'f':
			current.broken = value != ""
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := finish(); err != nil {
		return nil, err
	}
	return packages, nil
}

func parseDependency(raw string) (dependency, bool) {
	if raw == "" || strings.ContainsAny(raw, " \t\r\n@!") {
		return dependency{}, false
	}
	i := strings.IndexAny(raw, "<>=~")
	if i < 0 {
		if !depName.MatchString(raw) {
			return dependency{}, false
		}
		return dependency{name: raw}, true
	}
	name := raw[:i]
	if !depName.MatchString(name) {
		return dependency{}, false
	}
	rest := raw[i:]
	for _, op := range []string{">=", "<=", "==", ">", "<", "=", "~"} {
		if strings.HasPrefix(rest, op) && len(rest) > len(op) {
			return dependency{name: name, op: op, version: rest[len(op):]}, true
		}
	}
	return dependency{}, false
}
