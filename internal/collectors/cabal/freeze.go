package cabal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const maxFreezeBytes = 16 << 20

var pinnedVersion = regexp.MustCompile(`^(?:any\.)?([A-Za-z0-9][A-Za-z0-9-]{0,127})\s*==\s*([0-9]+(?:\.[0-9]+)*)$`)
var fieldName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*:`)

// CollectFreeze inventories exact version choices from a Cabal freeze file.
// Constraint flags and source repository selection do not establish a package
// dependency graph or prove the bytes currently installed on a machine.
func CollectFreeze(filename, project string) (model.Document, error) {
	file, err := os.Open(filename)
	if err != nil {
		return model.Document{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxFreezeBytes {
		return model.Document{}, errors.New("Cabal freeze file size is invalid or exceeds 16 MiB")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return model.Document{}, err
	}
	doc := common.NewDocument(filename, project, "cabal", data)
	baseEvidence := common.Evidence(filename, "cabal-freeze", "", data)
	var constraints strings.Builder
	seenField, inConstraints := false, false
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if fieldName.MatchString(line) {
			field, remainder, _ := strings.Cut(line, ":")
			inConstraints = strings.EqualFold(field, "constraints")
			if inConstraints {
				seenField = true
				if constraints.Len() > 0 {
					constraints.WriteString(",")
				}
				constraints.WriteString(" ")
				constraints.WriteString(remainder)
			}
			continue
		}
		if inConstraints {
			constraints.WriteString(" ")
			constraints.WriteString(trimmed)
		}
	}
	if !seenField {
		return model.Document{}, errors.New("Cabal freeze file has no constraints field")
	}
	seen := map[string]string{}
	for i, raw := range strings.Split(constraints.String(), ",") {
		constraint := strings.TrimSpace(raw)
		if constraint == "" {
			continue
		}
		match := pinnedVersion.FindStringSubmatch(constraint)
		if match == nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "cabal_freeze_unversioned_constraint", Name: constraint})
			continue
		}
		name, version := match[1], match[2]
		key := strings.ToLower(name)
		if prior, exists := seen[key]; exists {
			if prior != version {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "duplicate_spec", Name: name})
			}
			continue
		}
		seen[key] = version
		evidence := baseEvidence
		evidence.Pointer = fmt.Sprintf("/constraints/%d", i)
		id := "cabal-freeze:" + common.ID(filename+"\x00"+key+"\x00"+version)
		doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: name, Version: version, Evidence: []model.Evidence{evidence}})
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "pinned", Evidence: evidence})
		if len(doc.Components) > 100000 {
			return model.Document{}, errors.New("Cabal freeze file has too many package pins")
		}
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "cabal_freeze_graph_unavailable"},
		model.Issue{Code: "cabal_freeze_origin_unverified"},
		model.Issue{Code: "manifest_freshness_unverified"})
	common.Finalize(&doc)
	return doc, nil
}
