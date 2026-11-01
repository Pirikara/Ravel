package python

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Pirikara/Ravel/internal/model"
)

// InstalledRecord supplies the verified metadata bytes and component from
// CollectInstalledMetadata for dependency linking within one image.
type InstalledRecord struct {
	Component               model.Component
	Metadata                []byte
	MetadataPath            string
	EggRequirements         []byte
	EggRequirementsEvidence model.Evidence
}

type installedRequirementText struct {
	value    string
	evidence model.Evidence
}

type eggRequirementLine struct {
	value string
	line  int
}

type installedRequirement struct {
	name, exactVersion, constraint, marker, extras string
}

var installedVersionClause = regexp.MustCompile(`^(===|~=|==|!=|<=|>=|<|>)\s*([A-Za-z0-9.*+!_-]+)$`)

// LinkInstalledRequirements connects Requires-Dist entries only to packages
// found in the same site-packages/dist-packages directory. Unverified version
// constraints and environment markers remain conditional in Ravel JSON.
func LinkInstalledRequirements(doc *model.Document, records []InstalledRecord) {
	byEnvironment := map[string]map[string][]InstalledRecord{}
	for _, record := range records {
		environment := installedMetadataEnvironment(record.MetadataPath)
		if byEnvironment[environment] == nil {
			byEnvironment[environment] = map[string][]InstalledRecord{}
		}
		name := normalized(record.Component.Name)
		byEnvironment[environment][name] = append(byEnvironment[environment][name], record)
	}
	seenEdges := map[string]bool{}
	for _, record := range records {
		headers, _ := parseWheelHeaders(record.Metadata)
		environment := installedMetadataEnvironment(record.MetadataPath)
		index := 0
		var requirements []installedRequirementText
		for _, header := range headers {
			if header.name != "requires-dist" {
				continue
			}
			evidence := record.Component.Evidence[0]
			evidence.Pointer = fmt.Sprintf("Requires-Dist/%d", index)
			index++
			requirements = append(requirements, installedRequirementText{value: header.value, evidence: evidence})
		}
		if record.EggRequirementsEvidence.InputPath != "" {
			lines, invalidLines := parseEggRequirements(record.EggRequirements)
			for _, line := range invalidLines {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "python_requirement_unparsed", Name: record.Component.Name, Line: line})
			}
			for _, line := range lines {
				evidence := record.EggRequirementsEvidence
				evidence.Line = line.line
				requirements = append(requirements, installedRequirementText{value: line.value, evidence: evidence})
			}
		}
		for _, entry := range requirements {
			requirement, ok := parseInstalledRequirement(entry.value)
			if !ok {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "python_requirement_unparsed", Name: record.Component.Name, Line: entry.evidence.Line})
				continue
			}
			if requirement.extras != "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "requested_extra_graph_unavailable", Name: requirement.name})
			}
			if requirement.constraint != "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dependency_constraint_unverified", Name: requirement.name, Scope: record.Component.Name})
			}
			if requirement.marker != "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: requirement.name, Scope: record.Component.Name})
			}
			candidates := byEnvironment[environment][normalized(requirement.name)]
			var matched []InstalledRecord
			for _, candidate := range candidates {
				if requirement.exactVersion == "" || candidate.Component.Version == requirement.exactVersion {
					matched = append(matched, candidate)
				}
			}
			if len(matched) == 0 {
				code := "unresolved_dependency"
				if requirement.marker != "" {
					code = "conditional_dependency_unresolved"
				}
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: requirement.name, Scope: record.Component.Name})
				continue
			}
			condition := ""
			if requirement.marker != "" {
				condition = "marker=(" + requirement.marker + ")"
			}
			if requirement.constraint != "" {
				if condition != "" {
					condition += " && "
				}
				condition += "constraint=(" + requirement.constraint + ")"
			}
			if len(matched) > 1 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_dependency", Name: requirement.name, Scope: record.Component.Name})
				if condition != "" {
					condition += " && "
				}
				condition += "candidate=" + normalized(requirement.name)
			}
			for _, candidate := range matched {
				key := record.Component.ID + "\x00" + candidate.Component.ID + "\x00" + condition
				if seenEdges[key] {
					continue
				}
				seenEdges[key] = true
				doc.Edges = append(doc.Edges, model.Edge{From: record.Component.ID, To: candidate.Component.ID, Kind: "depends_on", Condition: condition, Evidence: entry.evidence})
			}
		}
	}
}

// parseEggRequirements converts the historical section headers into explicit
// conditions while preserving line numbers for source evidence.
func parseEggRequirements(data []byte) ([]eggRequirementLine, []int) {
	if !utf8.Valid(data) || strings.ContainsRune(string(data), '\x00') {
		return nil, []int{0}
	}
	var requirements []eggRequirementLine
	var invalidLines []int
	sectionCondition := ""
	sectionValid := true
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				invalidLines = append(invalidLines, i+1)
				sectionValid = false
				continue
			}
			section := line[1 : len(line)-1]
			extra, marker, hasMarker := strings.Cut(section, ":")
			if extra != "" && !installedDistributionName.MatchString(extra) || hasMarker && (len(marker) > 1024 || strings.ContainsAny(marker, "\x00\r\n@") || strings.Contains(marker, "://")) {
				invalidLines = append(invalidLines, i+1)
				sectionValid = false
				continue
			}
			sectionValid = true
			sectionCondition = ""
			if marker != "" {
				sectionCondition = "(" + marker + ")"
			}
			if extra != "" {
				if sectionCondition != "" {
					sectionCondition += " and "
				}
				sectionCondition += `extra == "` + extra + `"`
			}
			continue
		}
		if !sectionValid {
			invalidLines = append(invalidLines, i+1)
			continue
		}
		if sectionCondition != "" {
			if before, marker, found := strings.Cut(line, ";"); found {
				line = strings.TrimSpace(before) + "; (" + strings.TrimSpace(marker) + ") and " + sectionCondition
			} else {
				line += "; " + sectionCondition
			}
		}
		requirements = append(requirements, eggRequirementLine{value: line, line: i + 1})
	}
	return requirements, invalidLines
}

func parseInstalledRequirement(raw string) (installedRequirement, bool) {
	text := strings.TrimSpace(raw)
	if text == "" || len(text) > 4096 {
		return installedRequirement{}, false
	}
	i := 0
	for i < len(text) && (text[i] >= 'A' && text[i] <= 'Z' || text[i] >= 'a' && text[i] <= 'z' || text[i] >= '0' && text[i] <= '9' || text[i] == '-' || text[i] == '_' || text[i] == '.') {
		i++
	}
	name := text[:i]
	if !installedDistributionName.MatchString(name) {
		return installedRequirement{}, false
	}
	rest := strings.TrimSpace(text[i:])
	requirement := installedRequirement{name: name}
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return installedRequirement{}, false
		}
		var extras []string
		for _, item := range strings.Split(rest[1:end], ",") {
			item = strings.TrimSpace(item)
			if !installedDistributionName.MatchString(item) {
				return installedRequirement{}, false
			}
			extras = append(extras, normalized(item))
		}
		requirement.extras = strings.Join(extras, ",")
		rest = strings.TrimSpace(rest[end+1:])
	}
	if before, marker, found := strings.Cut(rest, ";"); found {
		rest = strings.TrimSpace(before)
		marker = strings.TrimSpace(marker)
		if marker == "" || len(marker) > 1024 || strings.ContainsAny(marker, "\x00\r\n@") || strings.Contains(marker, "://") {
			return installedRequirement{}, false
		}
		requirement.marker = marker
	}
	if strings.HasPrefix(rest, "@") {
		return installedRequirement{}, false // A direct URL is not resolved here.
	}
	if strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
		rest = strings.TrimSpace(rest[1 : len(rest)-1])
	}
	if rest == "" {
		return requirement, true
	}
	var clauses []string
	var exactVersion string
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		match := installedVersionClause.FindStringSubmatch(part)
		if match == nil {
			return installedRequirement{}, false
		}
		clauses = append(clauses, match[1]+match[2])
		if match[1] == "==" && !strings.Contains(match[2], "*") {
			exactVersion = match[2]
		}
	}
	if len(clauses) == 1 && exactVersion != "" {
		requirement.exactVersion = exactVersion
	} else {
		requirement.constraint = strings.Join(clauses, ",")
	}
	return requirement, true
}
