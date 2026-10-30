package npm

import (
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"

	"ravel/internal/model"
)

// InstalledRecord provides a verified package.json and its component for
// dependency linking within the final OCI filesystem.
type InstalledRecord struct {
	Component    model.Component
	Metadata     []byte
	MetadataPath string
}

var (
	installedNodeExactVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	installedNodeSafeRange    = regexp.MustCompile(`^[0-9*^~<>=][A-Za-z0-9^~<>=|.*+!_ -]*$`)
)

// LinkInstalledDependencies links declared package dependencies to observed
// manifests in the same node_modules tree. Ancestor lookup and unverified
// version ranges remain conditional because other filesystem entries or
// package manager layouts can alter runtime resolution.
func LinkInstalledDependencies(doc *model.Document, records []InstalledRecord) {
	byPath := map[string]InstalledRecord{}
	for _, record := range records {
		byPath[record.MetadataPath] = record
	}
	seen := map[string]bool{}
	for _, record := range records {
		fields, err := decodeUniqueObject(record.Metadata)
		if err != nil {
			continue // CollectInstalledPackage already validated the JSON.
		}
		optionalOverrides := map[string]bool{}
		optionalInvalid := false
		optionalRaw := bytes.TrimSpace(fields["optionalDependencies"])
		if len(optionalRaw) > 0 && !bytes.Equal(optionalRaw, []byte("null")) {
			values, err := decodeUniqueObject(optionalRaw)
			if err != nil {
				optionalInvalid = true
			} else {
				for name := range values {
					optionalOverrides[name] = true
				}
			}
		}
		for _, field := range []string{"dependencies", "optionalDependencies", "peerDependencies"} {
			if field == "dependencies" && optionalInvalid {
				continue
			}
			raw := bytes.TrimSpace(fields[field])
			if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
				continue
			}
			values, err := decodeUniqueObject(raw)
			if err != nil {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_dependency_manifest_invalid", Name: record.Component.Name, Scope: field})
				continue
			}
			dependencies := map[string]string{}
			valid := true
			for name, value := range values {
				var specifier string
				if json.Unmarshal(value, &specifier) != nil {
					valid = false
					break
				}
				dependencies[name] = specifier
			}
			if !valid {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_dependency_manifest_invalid", Name: record.Component.Name, Scope: field})
				continue
			}
			names := make([]string, 0, len(dependencies))
			for name := range dependencies {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if field == "dependencies" && optionalOverrides[name] {
					continue // npm gives optionalDependencies precedence.
				}
				if len(name) > 214 || !installedNodeName.MatchString(name) {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_dependency_manifest_invalid", Name: record.Component.Name, Scope: field})
					continue
				}
				target, direct, found := resolveInstalledNode(byPath, record.MetadataPath, name)
				if !found {
					code := "unresolved_dependency"
					if field != "dependencies" {
						code = "conditional_dependency_unresolved"
					}
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name, Scope: record.Component.Name})
					continue
				}
				var conditions []string
				if field == "optionalDependencies" {
					conditions = append(conditions, "optional")
				} else if field == "peerDependencies" {
					conditions = append(conditions, "peer")
				}
				if !direct {
					conditions = append(conditions, "resolution=ancestor_lookup")
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_resolution_unverified", Name: name, Scope: record.Component.Name})
				}
				if target.Component.Name != name {
					conditions = append(conditions, "alias=unverified")
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_package_alias_unverified", Name: name, Scope: record.Component.Name})
				}
				specifier := strings.TrimSpace(dependencies[name])
				switch {
				case installedNodeExactVersion.MatchString(specifier):
					if specifier != target.Component.Version {
						doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name, Scope: record.Component.Name})
						continue
					}
				case specifier == "*" || specifier == "":
				case len(specifier) <= 128 && installedNodeSafeRange.MatchString(specifier):
					conditions = append(conditions, "constraint=("+specifier+")")
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dependency_constraint_unverified", Name: name, Scope: record.Component.Name})
				default:
					conditions = append(conditions, "specifier=unverified")
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_dependency_specifier_unverified", Name: name, Scope: record.Component.Name})
				}
				condition := strings.Join(conditions, " && ")
				key := record.Component.ID + "\x00" + target.Component.ID + "\x00" + field + "\x00" + condition
				if seen[key] {
					continue
				}
				seen[key] = true
				evidence := record.Component.Evidence[0]
				evidence.Pointer = "/" + field + "/" + strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
				doc.Edges = append(doc.Edges, model.Edge{From: record.Component.ID, To: target.Component.ID, Kind: "depends_on", Condition: condition, Evidence: evidence})
			}
		}
	}
}

func resolveInstalledNode(byPath map[string]InstalledRecord, metadataPath, name string) (InstalledRecord, bool, bool) {
	base := path.Dir(metadataPath)
	first := true
	for {
		if path.Base(base) != "node_modules" {
			candidate := path.Join(base, "node_modules", name, "package.json")
			if target, found := byPath[candidate]; found {
				return target, first, true
			}
		}
		if base == "." {
			break
		}
		base = path.Dir(base)
		first = false
	}
	return InstalledRecord{}, false, false
}
