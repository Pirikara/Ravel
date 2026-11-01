package mix

import (
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

const maxLockBytes = 16 << 20

var packageName = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,127}$`)

type locked struct {
	key, id string
	deps    term
}

func Collect(filename, project string) (model.Document, error) {
	file, err := os.Open(filename)
	if err != nil {
		return model.Document{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxLockBytes {
		return model.Document{}, errors.New("Mix lockfile size is invalid or exceeds 16 MiB")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return model.Document{}, err
	}
	root, err := parseLiteral(data)
	if err != nil {
		return model.Document{}, err
	}
	doc := common.NewDocument(filename, project, "mix", data)
	baseEvidence := common.Evidence(filename, "mix-lock", "", data)
	byKey := map[string]locked{}
	for _, pair := range root.pairs {
		key, value := pair.key, pair.value
		if key.kind != "string" || !packageName.MatchString(key.value) || value.kind != "tuple" || len(value.elems) == 0 || value.elems[0].kind != "atom" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "mix_lock_entry_invalid", Line: key.line})
			continue
		}
		if _, exists := byKey[key.value]; exists {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "duplicate_spec", Name: key.value, Line: key.line})
			continue
		}
		evidence := baseEvidence
		evidence.Line = key.line
		evidence.Pointer = "/" + key.value
		component := model.Component{ID: "mix:" + common.ID(filename+"\x00"+key.value), Kind: "package", Name: key.value, Evidence: []model.Evidence{evidence}}
		switch value.elems[0].value {
		case "hex":
			if len(value.elems) < 7 || value.elems[1].kind != "atom" || !packageName.MatchString(value.elems[1].value) || value.elems[2].kind != "string" || !validLiteralVersion(value.elems[2].value) || value.elems[5].kind != "list" || value.elems[6].kind != "string" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "mix_lock_entry_invalid", Name: key.value, Line: key.line})
				continue
			}
			component.Version = value.elems[2].value
			if value.elems[1].value != key.value {
				component.Context = "hex-package=" + value.elems[1].value
			}
			if value.elems[6].value == "hexpm" {
				component.PURL = packageurl.NewPackageURL("hex", "", value.elems[1].value, component.Version, nil, "").ToString()
			} else {
				component.Context += ";repository=non-default"
				component.Context = strings.TrimPrefix(component.Context, ";")
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "mix_registry_unverified", Name: key.value})
			}
			byKey[key.value] = locked{key: key.value, id: component.ID, deps: value.elems[5]}
		case "git":
			if len(value.elems) < 3 || value.elems[1].kind != "string" || value.elems[2].kind != "string" || !validLiteralVersion(value.elems[2].value) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "mix_lock_entry_invalid", Name: key.value, Line: key.line})
				continue
			}
			component.Version = value.elems[2].value
			if clean := safeurl.Clean(value.elems[1].value); clean != "" {
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: component.ID, Kind: "vcs", SafeURL: clean, Revision: component.Version, Status: "declared", Evidence: evidence})
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: key.value})
			}
			byKey[key.value] = locked{key: key.value, id: component.ID}
		case "path":
			if len(value.elems) < 2 || value.elems[1].kind != "string" || value.elems[1].value == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "mix_lock_entry_invalid", Name: key.value, Line: key.line})
				continue
			}
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: component.ID, Kind: "local", LocalPath: value.elems[1].value, Status: "declared", Evidence: evidence})
			byKey[key.value] = locked{key: key.value, id: component.ID}
		default:
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "mix_source_unhandled", Name: key.value, Line: key.line})
			continue
		}
		doc.Components = append(doc.Components, component)
	}
	for _, item := range byKey {
		if item.deps.kind != "list" {
			continue
		}
		for _, dep := range item.deps.elems {
			if dep.kind != "tuple" || len(dep.elems) < 2 || dep.elems[0].kind != "atom" || dep.elems[1].kind != "string" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "mix_dependency_invalid", Name: item.key, Line: dep.line})
				continue
			}
			name := dep.elems[0].value
			optional := false
			if len(dep.elems) >= 3 && dep.elems[2].kind == "list" {
				for _, option := range dep.elems[2].elems {
					if option.kind == "keyword" && option.value == "optional" && len(option.elems) == 1 && option.elems[0].value == "true" {
						optional = true
					}
				}
			}
			child, found := byKey[name]
			if !found {
				if !optional {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "mix_dependency_unresolved", Name: name, Scope: item.key, Line: dep.line})
				}
				continue
			}
			condition := "version constraint unverified"
			if optional {
				condition += "; optional"
			}
			evidence := baseEvidence
			evidence.Line = dep.line
			evidence.Pointer = "/" + item.key + "/dependencies/" + name
			doc.Edges = append(doc.Edges, model.Edge{From: item.id, To: child.id, Kind: "requires", Condition: condition, Evidence: evidence})
		}
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "mix_direct_dependencies_unavailable"},
		model.Issue{Code: "mix_dependency_constraints_unverified"},
		model.Issue{Code: "mix_distribution_origin_unverified"})
	common.Finalize(&doc)
	return doc, nil
}

func validLiteralVersion(value string) bool {
	return value != "" && len(value) <= 128 && strings.IndexFunc(value, unicode.IsControl) < 0
}
