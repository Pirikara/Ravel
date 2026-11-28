package dpkg

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
	"sort"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const maxStatusFile = 128 << 20

var (
	packageName  = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	architecture = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	relation     = regexp.MustCompile(`^([a-z0-9][a-z0-9+.-]*)(?::(any|native|[a-z0-9][a-z0-9-]*))?(?:\s*\(\s*(<<|<=|=|>=|>>)\s*([^\s()]+)\s*\))?$`)
)

type statusPackage struct {
	name, version, arch, status, multiArch string
	depends, preDepends, provides          string
	line, dependsLine, preDependsLine      int
	ref                                    string
	source, digest, collector              string
}

func (p statusPackage) evidence(line int) model.Evidence {
	method := "installed-database"
	if p.collector == "dpkg-status-fragment" {
		method = "installed-metadata"
	}
	return model.Evidence{Collector: p.collector, InputPath: p.source, InputDigest: p.digest, Line: line, Method: method}
}

type dependency struct {
	name, arch, op, version string
}

type virtualProvider struct {
	index   int
	version string
}

// Collect reads the dpkg installed-package database from a filesystem tree.
// It does not infer the distribution or repository from package names alone.
func Collect(file, project string) (model.Document, error) {
	f, err := os.Open(file)
	if err != nil {
		return model.Document{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStatusFile+1))
	if err != nil {
		return model.Document{}, err
	}
	if len(data) > maxStatusFile {
		return model.Document{}, errors.New("dpkg status file exceeded size limit")
	}
	return CollectBytes(data, file, project)
}

// CollectBytes reads a status database from an already verified container
// layer. source identifies the database bytes, rather than a host file.
func CollectBytes(data []byte, source, project string) (model.Document, error) {
	if len(data) > maxStatusFile {
		return model.Document{}, errors.New("dpkg status file exceeded size limit")
	}
	packages, err := readStatus(data)
	if err != nil {
		return model.Document{}, err
	}
	hash := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	for i := range packages {
		packages[i].source, packages[i].digest, packages[i].collector = source, digest, "dpkg-status"
	}
	return collectPackages(packages, source, project)
}

// CollectFragments reads package control records kept by stripped images under
// dpkg/status.d. Unlike the active status database, these records may omit
// Status. Evidence always identifies the original fragment, never a fabricated
// combined status file. Dependencies can reference packages in other fragments.
func CollectFragments(fragments map[string][]byte, source, project string) (model.Document, error) {
	if len(fragments) > 4096 {
		return model.Document{}, errors.New("too many dpkg status fragments")
	}
	names := make([]string, 0, len(fragments))
	for name := range fragments {
		names = append(names, name)
	}
	sort.Strings(names)
	var packages []statusPackage
	total := 0
	for _, name := range names {
		data := fragments[name]
		total += len(data)
		if len(data) > 1<<20 || total > 64<<20 {
			return model.Document{}, errors.New("dpkg status fragments exceeded size limit")
		}
		rows, err := readStatusMode(data, true)
		if err != nil {
			return model.Document{}, fmt.Errorf("invalid dpkg status fragment %s: %w", name, err)
		}
		hash := sha256.Sum256(data)
		for i := range rows {
			rows[i].source, rows[i].digest, rows[i].collector = name, "sha256:"+hex.EncodeToString(hash[:]), "dpkg-status-fragment"
		}
		if len(packages)+len(rows) > 200000 {
			return model.Document{}, errors.New("dpkg fragments have too many stanzas")
		}
		packages = append(packages, rows...)
	}
	return collectPackages(packages, source, project)
}

func collectPackages(packages []statusPackage, source, project string) (model.Document, error) {
	doc := common.NewDocument(source, project, "dpkg", nil)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: "dpkg status database"})
	byName := map[string][]int{}
	seen := map[string]bool{}
	for i := range packages {
		p := &packages[i]
		key := p.name + "\x00" + p.arch
		if seen[key] {
			return model.Document{}, fmt.Errorf("duplicate installed dpkg package %s:%s", p.name, p.arch)
		}
		seen[key] = true
		p.ref = "dpkg:" + common.ID(key+"\x00"+p.version)
		context := "status=installed"
		if p.status == "" {
			context = "metadata=dpkg-status-fragment"
		}
		doc.Components = append(doc.Components, model.Component{ID: p.ref, Kind: "package", Name: p.name, Version: p.version, Platform: p.arch, Context: context, Evidence: []model.Evidence{p.evidence(p.line)}})
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: p.ref, Kind: "installed", Evidence: p.evidence(p.line)})
		byName[p.name] = append(byName[p.name], i)
		if p.status != "" && strings.Fields(p.status)[1] != "ok" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dpkg_package_unhealthy", Name: p.name})
		}
	}
	providers := map[string][]virtualProvider{}
	for i, p := range packages {
		if p.provides == "" {
			continue
		}
		for _, raw := range splitRelations(p.provides, ',') {
			dep, ok := parseRelation(raw)
			if !ok || dep.arch != "" || dep.op != "" && dep.op != "=" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dependency_constraint_unverified", Name: p.name, Scope: "Provides"})
				continue
			}
			providers[dep.name] = append(providers[dep.name], virtualProvider{index: i, version: dep.version})
		}
	}
	seenEdges := map[string]bool{}
	for _, p := range packages {
		for _, field := range []struct {
			name, value string
			line        int
		}{{"Depends", p.depends, p.dependsLine}, {"Pre-Depends", p.preDepends, p.preDependsLine}} {
			if field.value == "" {
				continue
			}
			for _, group := range splitRelations(field.value, ',') {
				alternatives := splitRelations(group, '|')
				matches := map[string]bool{}
				unverified := false
				for _, raw := range alternatives {
					dep, ok := parseRelation(raw)
					if !ok {
						unverified = true
						continue
					}
					if dep.arch == "native" {
						unverified = true
					}
					consider := func(candidate int, version string) {
						q := packages[candidate]
						matchesArch, uncertainArch := architectureMatches(p.arch, dep.arch, q.arch, q.multiArch)
						if !matchesArch {
							return
						}
						if uncertainArch {
							unverified = true
						}
						if dep.op != "" {
							if version == "" {
								return
							}
							cmp, valid := compareVersions(version, dep.version)
							if !valid {
								unverified = true
								return
							}
							if !satisfies(cmp, dep.op) {
								return
							}
						}
						matches[q.ref] = true
					}
					for _, candidate := range byName[dep.name] {
						consider(candidate, packages[candidate].version)
					}
					for _, provider := range providers[dep.name] {
						consider(provider.index, provider.version)
					}
				}
				if unverified {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dependency_constraint_unverified", Name: p.name, Line: field.line, Scope: field.name})
				}
				if len(matches) == 0 {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: strings.TrimSpace(group), Line: field.line, Scope: p.name})
					continue
				}
				condition := ""
				if len(matches) > 1 || unverified {
					condition = "alternative=" + strings.TrimSpace(group)
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: p.name, Line: field.line})
				}
				for to := range matches {
					kind := "depends_on"
					if field.name == "Pre-Depends" {
						kind = "pre_depends_on"
					}
					key := p.ref + "\x00" + to + "\x00" + kind + "\x00" + condition
					if seenEdges[key] {
						continue
					}
					seenEdges[key] = true
					doc.Edges = append(doc.Edges, model.Edge{From: p.ref, To: to, Kind: kind, Condition: condition, Evidence: p.evidence(field.line)})
				}
			}
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func readStatus(data []byte) ([]statusPackage, error) {
	return readStatusMode(data, false)
}

func readStatusMode(data []byte, fragment bool) ([]statusPackage, error) {
	var packages []statusPackage
	var current statusPackage
	seen := map[string]bool{}
	field := ""
	line := 0
	stanzas := 0
	flush := func() error {
		if len(seen) == 0 {
			return nil
		}
		stanzas++
		if stanzas > 200000 {
			return errors.New("dpkg status file has too many stanzas")
		}
		state := strings.Fields(current.status)
		missingState := fragment && current.status == ""
		if len(state) != 3 && !missingState {
			return fmt.Errorf("invalid dpkg Status field near line %d", current.line)
		}
		if missingState || state[2] == "installed" {
			if !packageName.MatchString(current.name) || !architecture.MatchString(current.arch) || current.version == "" || strings.ContainsAny(current.version, " \t\r\n") {
				return fmt.Errorf("installed dpkg package has invalid identity near line %d", current.line)
			}
			packages = append(packages, current)
		}
		current = statusPackage{}
		seen = map[string]bool{}
		field = ""
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		line++
		text := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.TrimSpace(text) == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		if text[0] == ' ' || text[0] == '\t' {
			if field == "depends" {
				current.depends += " " + strings.TrimSpace(text)
			} else if field == "pre-depends" {
				current.preDepends += " " + strings.TrimSpace(text)
			} else if field == "provides" {
				current.provides += " " + strings.TrimSpace(text)
			} else if field == "" {
				return nil, fmt.Errorf("orphan dpkg continuation near line %d", line)
			}
			continue
		}
		name, value, ok := strings.Cut(text, ":")
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid dpkg field near line %d", line)
		}
		field = strings.ToLower(name)
		if seen[field] {
			return nil, fmt.Errorf("duplicate dpkg field %s near line %d", name, line)
		}
		seen[field] = true
		value = strings.TrimSpace(value)
		if current.line == 0 {
			current.line = line
		}
		switch field {
		case "package":
			current.name = value
		case "version":
			current.version = value
		case "architecture":
			current.arch = value
		case "multi-arch":
			current.multiArch = value
		case "status":
			current.status = value
		case "depends":
			current.depends, current.dependsLine = value, line
		case "pre-depends":
			current.preDepends, current.preDependsLine = value, line
		case "provides":
			current.provides = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("invalid dpkg status file: %w", err)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if stanzas == 0 {
		return nil, errors.New("empty dpkg status file")
	}
	return packages, nil
}

func splitRelations(raw string, sep byte) []string {
	parts := []string{}
	depth, start := 0, 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if raw[i] == sep && depth == 0 {
			parts = append(parts, strings.TrimSpace(raw[start:i]))
			start = i + 1
		}
	}
	parts = append(parts, strings.TrimSpace(raw[start:]))
	return parts
}

func parseRelation(raw string) (dependency, bool) {
	match := relation.FindStringSubmatch(strings.TrimSpace(raw))
	if match == nil {
		return dependency{}, false
	}
	return dependency{name: match[1], arch: match[2], op: match[3], version: match[4]}, true
}

func architectureMatches(source, requested, candidate, multiArch string) (bool, bool) {
	switch requested {
	case "native":
		return false, true // the native architecture is not recorded in status
	case "any":
		return multiArch == "allowed", false
	case "":
		if candidate == source || multiArch == "foreign" {
			return true, false
		}
		if candidate == "all" || source == "all" {
			return true, true // status alone does not identify the native architecture
		}
		return false, false
	default:
		if requested == candidate {
			return true, false
		}
		if candidate == "all" {
			return true, true
		}
		return false, false
	}
}
