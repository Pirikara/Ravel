package bundler

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

var gemspecBlock = regexp.MustCompile(`(?m)^\s*Gem::Specification\.new\s+do\s+\|([A-Za-z_][A-Za-z0-9_]*)\|`)
var gemspecVersionConstant = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_:]*::VERSION\b`)
var gemspecVersionLiteral = regexp.MustCompile(`^[0-9][0-9A-Za-z.+_-]{0,127}$`)
var rubyVersionAssignment = regexp.MustCompile(`(?m)^\s*VERSION\s*=\s*(.+)$`)
var rubyRequire = regexp.MustCompile(`(?m)^\s*require(_relative)?\s+["']([^"']+/version)["']\s*(?:#.*)?$`)

// CollectGemspec reads literal identity from a source gemspec. It never runs Ruby.
func CollectGemspec(file, project string) (model.Document, error) {
	info, err := os.Stat(file)
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return model.Document{}, fmt.Errorf("invalid or oversized gemspec")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	block := gemspecBlock.FindSubmatch(data)
	if block == nil {
		return model.Document{}, fmt.Errorf("no literal Gem::Specification block")
	}
	variable := regexp.QuoteMeta(string(block[1]))
	assignment := func(field string) string {
		pattern := regexp.MustCompile(`(?m)^\s*` + variable + `\.` + field + `\s*=\s*(.+)$`)
		matches := pattern.FindAllSubmatch(data, 2)
		if len(matches) != 1 {
			return ""
		}
		return strings.TrimSpace(string(matches[0][1]))
	}
	name := rubyLiteral(assignment("name"))
	if !classicGemName(name) {
		return model.Document{}, fmt.Errorf("gemspec name is not a literal package name")
	}
	versionExpression := assignment("version")
	version := ""
	versionFile := ""
	if literal := rubyLiteral(versionExpression); gemspecVersionLiteral.MatchString(literal) {
		version = literal
	} else if gemspecVersionConstant.MatchString(versionExpression) {
		version, versionFile = resolveGemspecVersion(file, data)
	}
	evidence := common.Evidence(file, "ruby-gemspec", "/name", data)
	evidence.Method = "source-analysis"
	doc := common.NewDocument(file, project, "gemspec", data)
	component := model.Component{ID: "gemspec:" + common.ID(file+"\x00"+name), Kind: "package", Name: name, Version: version, Evidence: []model.Evidence{evidence}}
	if versionFile != "" {
		versionData, err := os.ReadFile(versionFile)
		if err == nil {
			versionEvidence := common.Evidence(versionFile, "ruby-version-constant", "/VERSION", versionData)
			versionEvidence.Method = "source-analysis"
			component.Evidence = append(component.Evidence, versionEvidence)
			doc.Sources = append(doc.Sources, versionFile)
		}
	}
	doc.Components = append(doc.Components, component)
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: component.ID, Kind: "direct", Evidence: evidence})
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: component.ID, Kind: "local", LocalPath: filepath.Dir(file), Status: "declared", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "declared_dependencies_unresolved", Name: name})
	if version == "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "version_unresolved", Name: name})
	}
	common.Finalize(&doc)
	return doc, nil
}

func rubyLiteral(expression string) string {
	expression = strings.TrimSpace(expression)
	if len(expression) < 3 || expression[0] != expression[len(expression)-1] || expression[0] != '\'' && expression[0] != '"' || strings.ContainsAny(expression[1:len(expression)-1], "\r\n\\") || strings.ContainsRune(expression[1:len(expression)-1], rune(expression[0])) {
		return ""
	}
	return expression[1 : len(expression)-1]
}

func classicGemName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for _, char := range name {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func resolveGemspecVersion(file string, gemspec []byte) (string, string) {
	root := filepath.Dir(file)
	for _, match := range rubyRequire.FindAllSubmatch(gemspec, 32) {
		required := string(match[2]) + ".rb"
		candidates := []string{filepath.Join(root, required)}
		if len(match[1]) == 0 {
			candidates = append(candidates, filepath.Join(root, "lib", required))
		}
		for _, candidate := range candidates {
			relative, err := filepath.Rel(root, candidate)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				continue
			}
			info, err := os.Lstat(candidate)
			if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
				continue
			}
			data, err := os.ReadFile(candidate)
			if err != nil {
				continue
			}
			versions := rubyVersionAssignment.FindAllSubmatch(data, 2)
			if len(versions) == 1 {
				version := rubyLiteral(string(versions[0][1]))
				if gemspecVersionLiteral.MatchString(version) {
					return version, candidate
				}
			}
		}
	}
	return "", ""
}
