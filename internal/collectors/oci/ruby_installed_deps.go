package oci

import (
	"regexp"
	"strconv"
	"strings"

	"ravel/internal/model"
)

const (
	maxRubyDependenciesPerSpec = 128
	maxRubyDependenciesImage   = 50000
)

var rubyRuntimeDependencyCall = regexp.MustCompile(`^s\.(?:add_runtime_dependency|add_dependency)\(%q<([A-Za-z0-9][A-Za-z0-9_.-]{0,127})>\.freeze, \[(.*)\]\)$`)
var rubyRequirementLiteral = regexp.MustCompile(`^"((?:>=|<=|~>|!=|=|>|<) [0-9]+(?:\.[0-9]+)*)"\.freeze$`)
var rubyNumericVersion = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*$`)

type rubyInstalledRecord struct {
	component    model.Component
	metadata     []byte
	metadataPath string
}

type rubyInstalledDependency struct {
	name         string
	requirements []string
	line         int
}

// linkInstalledRubyDependencies observes declarative runtime dependency calls
// in generated gemspecs. It does not evaluate Ruby or assume a GEM_PATH across
// ordinary gem homes. A verified CRuby runtime exposes its matching default
// gems when the source gem home has no installed candidate. Installed versions
// may differ from activated versions.
func linkInstalledRubyDependencies(doc *model.Document, records []rubyInstalledRecord, runtimes map[string]rubyRuntimeState) {
	byHomeName := map[string][]model.Component{}
	byDefaultName := map[string][]model.Component{}
	defaultHome := rubyDefaultGemHome(runtimes)
	for _, record := range records {
		home := rubyGemHome(record.metadataPath)
		key := home + "\x00" + record.component.Name
		byHomeName[key] = append(byHomeName[key], record.component)
		if defaultHome != "" && home == defaultHome && strings.HasPrefix(record.metadataPath, defaultHome+"/specifications/default/") {
			byDefaultName[record.component.Name] = append(byDefaultName[record.component.Name], record.component)
		}
	}
	dependenciesSeen := 0
	for _, record := range records {
		dependencies, issues, calls := parseRubyRuntimeDependencies(record)
		dependenciesSeen += calls
		if dependenciesSeen > maxRubyDependenciesImage {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_installed_dependency_scan_limited"})
			return
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, issues...)
		byName := map[string]int{}
		for _, dependency := range dependencies {
			byName[dependency.name]++
		}
		for _, dependency := range dependencies {
			if byName[dependency.name] != 1 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_installed_dependency_ambiguous", Name: dependency.name, Scope: record.component.Name, Line: dependency.line})
				continue
			}
			home := rubyGemHome(record.metadataPath)
			key := home + "\x00" + dependency.name
			candidates := byHomeName[key]
			if len(candidates) == 0 && defaultHome != "" && home != defaultHome {
				candidates = byDefaultName[dependency.name]
			}
			if len(candidates) == 0 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_installed_dependency_unresolved", Name: dependency.name, Scope: record.component.Name, Line: dependency.line})
				continue
			}
			var matches []model.Component
			uncertain := false
			for _, candidate := range candidates {
				if strings.Contains(candidate.Context, ";gem_platform=") {
					uncertain = true
					continue
				}
				match, known := rubyRequirementsMatch(candidate.Version, dependency.requirements)
				if !known {
					uncertain = true
				} else if match {
					matches = append(matches, candidate)
				}
			}
			if uncertain {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_installed_dependency_constraint_unverified", Name: dependency.name, Scope: record.component.Name, Line: dependency.line})
				continue
			}
			if len(matches) == 0 || len(matches) == 1 && matches[0].ID == record.component.ID {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_installed_dependency_unresolved", Name: dependency.name, Scope: record.component.Name, Line: dependency.line})
				continue
			}
			if len(matches) != 1 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_installed_dependency_ambiguous", Name: dependency.name, Scope: record.component.Name, Line: dependency.line})
				continue
			}
			evidence := record.component.Evidence[0]
			evidence.Line = dependency.line
			evidence.Pointer = "Gem::Specification/runtime-dependency/" + dependency.name
			doc.Edges = append(doc.Edges, model.Edge{From: record.component.ID, To: matches[0].ID, Kind: "depends_on", Evidence: evidence})
		}
	}
}

// Default gem specifications are visible to the matching CRuby installation
// even when GEM_HOME names another directory. Require one verified runtime to
// avoid joining gem homes from unrelated Ruby installations.
func rubyDefaultGemHome(runtimes map[string]rubyRuntimeState) string {
	if len(runtimes) != 1 {
		return ""
	}
	for _, state := range runtimes {
		if state.status != "" || len(state.document.Components) != 1 || state.document.Components[0].Name != "ruby" {
			return ""
		}
		parts := strings.Split(state.document.Components[0].Version, ".")
		if len(parts) != 3 {
			return ""
		}
		return "usr/local/lib/ruby/gems/" + parts[0] + "." + parts[1] + ".0"
	}
	return ""
}

func rubyGemHome(filename string) string {
	home, _, _ := strings.Cut(filename, "/specifications/")
	return home
}

func parseRubyRuntimeDependencies(record rubyInstalledRecord) ([]rubyInstalledDependency, []model.Issue, int) {
	var dependencies []rubyInstalledDependency
	var issues []model.Issue
	calls := 0
	for i, line := range strings.Split(string(record.metadata), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "s.add_runtime_dependency") && !strings.HasPrefix(trimmed, "s.add_dependency") {
			continue
		}
		calls++
		if calls > maxRubyDependenciesPerSpec {
			issues = append(issues, model.Issue{Code: "ruby_installed_dependency_scan_limited", Name: record.component.Name})
			break
		}
		match := rubyRuntimeDependencyCall.FindStringSubmatch(trimmed)
		if match == nil {
			issues = append(issues, model.Issue{Code: "ruby_installed_dependency_unparsed", Name: record.component.Name, Line: i + 1})
			continue
		}
		dependency := rubyInstalledDependency{name: match[1], line: i + 1}
		if match[2] != "" {
			valid := true
			for _, raw := range strings.Split(match[2], ", ") {
				constraint := rubyRequirementLiteral.FindStringSubmatch(raw)
				if constraint == nil {
					valid = false
					break
				}
				dependency.requirements = append(dependency.requirements, constraint[1])
			}
			if !valid {
				issues = append(issues, model.Issue{Code: "ruby_installed_dependency_unparsed", Name: record.component.Name, Line: i + 1})
				continue
			}
		}
		dependencies = append(dependencies, dependency)
	}
	return dependencies, issues, calls
}

func rubyRequirementsMatch(version string, requirements []string) (match, known bool) {
	actual, ok := parseRubyNumericVersion(version)
	if !ok {
		return false, false
	}
	for _, requirement := range requirements {
		parts := strings.SplitN(requirement, " ", 2)
		if len(parts) != 2 {
			return false, false
		}
		want, ok := parseRubyNumericVersion(parts[1])
		if !ok {
			return false, false
		}
		comparison := compareRubyNumericVersions(actual, want)
		satisfied := false
		switch parts[0] {
		case ">=":
			satisfied = comparison >= 0
		case ">":
			satisfied = comparison > 0
		case "<=":
			satisfied = comparison <= 0
		case "<":
			satisfied = comparison < 0
		case "=":
			satisfied = comparison == 0
		case "!=":
			satisfied = comparison != 0
		case "~>":
			upper := append([]uint64(nil), want...)
			index := 0
			if len(upper) > 1 {
				index = len(upper) - 2
			}
			upper[index]++
			upper = upper[:index+1]
			satisfied = comparison >= 0 && compareRubyNumericVersions(actual, upper) < 0
		default:
			return false, false
		}
		if !satisfied {
			return false, true
		}
	}
	return true, true
}

func parseRubyNumericVersion(value string) ([]uint64, bool) {
	if len(value) > 128 || !rubyNumericVersion.MatchString(value) {
		return nil, false
	}
	parts := strings.Split(value, ".")
	if len(parts) > 16 {
		return nil, false
	}
	result := make([]uint64, 0, len(parts))
	for _, part := range parts {
		if len(part) > 9 {
			return nil, false
		}
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, false
		}
		result = append(result, value)
	}
	return result, true
}

func compareRubyNumericVersions(a, b []uint64) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		var left, right uint64
		if i < len(a) {
			left = a[i]
		}
		if i < len(b) {
			right = b[i]
		}
		if left < right {
			return -1
		}
		if left > right {
			return 1
		}
	}
	return 0
}
