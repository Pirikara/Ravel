package python

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

const maxRequirementsBytes = 8 << 20

var (
	requirementsNameRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9._,-]+\])?(.*)$`)
	requirementHash    = regexp.MustCompile(`(?:^|\s)--hash(?:=|\s+)([A-Za-z0-9]+):([0-9a-fA-F]+)(?:\s|$)`)
	requirementPin     = regexp.MustCompile(`^==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)$`)
)

// CollectRequirements records stated requirements. A requirements file is not
// evidence of an installed or resolved transitive graph.
func CollectRequirements(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	if len(data) > maxRequirementsBytes {
		return model.Document{}, fmt.Errorf("requirements file exceeds %d bytes", maxRequirementsBytes)
	}
	doc := common.NewDocument(file, project, "requirements", data)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "transitive_graph_unavailable"})
	seen := map[string]bool{}
	if err := collectRequirementsFile(&doc, file, 0, seen); err != nil {
		return model.Document{}, err
	}
	common.Finalize(&doc)
	return doc, nil
}

func collectRequirementsFile(doc *model.Document, file string, depth int, seen map[string]bool) error {
	if depth >= 16 {
		return fmt.Errorf("requirements include depth exceeds 16")
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	if seen[abs] {
		return fmt.Errorf("cyclic or repeated requirements include")
	}
	seen[abs] = true
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if len(data) > maxRequirementsBytes {
		return fmt.Errorf("requirements file exceeds %d bytes", maxRequirementsBytes)
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("requirements file is not UTF-8")
	}
	if depth > 0 {
		doc.Sources = append(doc.Sources, file)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxRequirementsBytes)
	var logical strings.Builder
	startLine, line := 0, 0
	for scanner.Scan() {
		line++
		part := strings.TrimSpace(scanner.Text())
		if line == 1 {
			part = strings.TrimPrefix(part, "\ufeff")
		}
		if startLine == 0 {
			startLine = line
		}
		continued := strings.HasSuffix(part, `\`) && !strings.HasSuffix(part, `\\`)
		if continued {
			part = strings.TrimSuffix(part, `\`)
		}
		logical.WriteString(part)
		if continued {
			logical.WriteByte(' ')
			continue
		}
		entry := stripRequirementComment(strings.TrimSpace(logical.String()))
		logical.Reset()
		if entry != "" {
			if err := collectRequirementLine(doc, file, data, startLine, entry, depth, seen); err != nil {
				return err
			}
		}
		startLine = 0
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if logical.Len() != 0 {
		return fmt.Errorf("unterminated requirements line continuation")
	}
	return nil
}

func stripRequirementComment(line string) string {
	if strings.HasPrefix(line, "#") {
		return ""
	}
	for i := 1; i < len(line); i++ {
		if line[i] == '#' && (line[i-1] == ' ' || line[i-1] == '\t') {
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

func collectRequirementLine(doc *model.Document, file string, data []byte, line int, entry string, depth int, seen map[string]bool) error {
	issue := func(code, name string) {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name, Line: line, Scope: file})
	}
	for _, option := range []string{"-r", "--requirement"} {
		if entry == option || strings.HasPrefix(entry, option+" ") || strings.HasPrefix(entry, option+"=") || option == "-r" && strings.HasPrefix(entry, "-r") {
			include := strings.TrimSpace(strings.TrimPrefix(entry, option))
			include = strings.TrimPrefix(include, "=")
			if include == "" || strings.ContainsAny(include, " \t") || strings.Contains(include, "://") || strings.Contains(include, "${") {
				issue("unsupported_include", "")
				return nil
			}
			return collectRequirementsFile(doc, filepath.Join(filepath.Dir(file), include), depth+1, seen)
		}
	}
	if strings.HasPrefix(entry, "-c") || strings.HasPrefix(entry, "--constraint") {
		issue("constraint_not_applied", "")
		return nil
	}
	if strings.HasPrefix(entry, "-") {
		issue("pip_option_not_evaluated", "")
		return nil
	}
	if strings.HasPrefix(entry, "https://") || strings.HasPrefix(entry, "http://") || strings.HasPrefix(entry, "./") || strings.HasPrefix(entry, "../") || strings.HasPrefix(entry, "/") || strings.HasPrefix(entry, "git+") {
		issue("unnamed_artifact_unresolved", "")
		return nil
	}
	var hashes []model.Hash
	for {
		location := requirementHash.FindStringSubmatchIndex(entry)
		if location == nil {
			break
		}
		alg, digest := strings.ToUpper(entry[location[2]:location[3]]), entry[location[4]:location[5]]
		if alg == "SHA256" && len(digest) == 64 {
			hashes = append(hashes, model.Hash{Alg: "SHA-256", Content: strings.ToLower(digest)})
		} else if alg == "SHA512" && len(digest) == 128 {
			hashes = append(hashes, model.Hash{Alg: "SHA-512", Content: strings.ToLower(digest)})
		} else {
			issue("unsupported_hash", "")
		}
		entry = strings.TrimSpace(entry[:location[0]] + " " + entry[location[1]:])
	}
	if strings.Contains(entry, "--hash") {
		issue("unsupported_hash", "")
		return nil
	}
	parts := requirementsNameRE.FindStringSubmatch(entry)
	if parts == nil {
		issue("unsupported_requirement", "")
		return nil
	}
	name, extras, remainder := parts[1], parts[2], strings.TrimSpace(parts[3])
	marker := ""
	if i := strings.Index(remainder, ";"); i >= 0 {
		marker, remainder = strings.TrimSpace(remainder[i+1:]), strings.TrimSpace(remainder[:i])
		if marker == "" {
			issue("unsupported_marker", name)
		}
	}
	version, source := "", ""
	if pin := requirementPin.FindStringSubmatch(remainder); pin != nil && !strings.Contains(pin[1], "*") {
		version = pin[1]
	} else if strings.HasPrefix(remainder, "@") {
		source = strings.TrimSpace(strings.TrimPrefix(remainder, "@"))
		if source == "" || strings.ContainsAny(source, " \t") {
			issue("unsupported_requirement", name)
			return nil
		}
	} else {
		issue("unresolved_version", name)
	}
	if extras != "" {
		issue("requested_extra_graph_unavailable", name)
	}
	if marker != "" {
		issue("conditional_graph", name)
	}
	if len(hashes) > 1 {
		issue("multiple_artifact_hashes_unassigned", name)
		hashes = nil
	}
	ref := "requirements:" + common.ID(file+"|"+fmt.Sprint(line)+"|"+name)
	ev := common.Evidence(file, "pip-requirements", fmt.Sprintf("line:%d", line), data)
	ev.Line = line
	component := model.Component{ID: ref, Kind: "package", Name: name, Version: version, Hashes: hashes, Evidence: []model.Evidence{ev}}
	if extras != "" {
		component.Context = "requestedExtras=" + strings.Trim(extras, "[]")
	}
	doc.Components = append(doc.Components, component)
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ref, Kind: "direct", Condition: marker, Evidence: ev})
	if source != "" {
		kind := "download_url"
		raw := source
		if strings.HasPrefix(raw, "git+") {
			kind, raw = "vcs", strings.TrimPrefix(raw, "git+")
		}
		if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
			clean := safeurl.Clean(raw)
			if clean == "" {
				issue("unsafe_or_invalid_source", name)
			} else {
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: kind, SafeURL: clean, Status: "declared", Evidence: ev})
			}
		} else {
			issue("unsupported_source", name)
		}
	} else {
		issue("missing_source", name)
	}
	return nil
}
