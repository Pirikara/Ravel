package common

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"ravel/internal/model"
)

func NewDocument(path, project, manager string, data []byte) model.Document {
	return model.Document{
		SchemaVersion: "0.1", Project: project, Source: path,
		Components: []model.Component{}, Edges: []model.Edge{}, Origins: []model.Origin{}, Development: []model.Development{},
		Coverage: model.Coverage{Manager: manager, GraphState: "complete_for_scope", OriginState: "complete_for_scope", Issues: []model.Issue{}},
	}
}

func Evidence(path, collector, pointer string, data []byte) model.Evidence {
	h := sha256.Sum256(data)
	return model.Evidence{Collector: collector, InputPath: path, InputDigest: "sha256:" + hex.EncodeToString(h[:]), Pointer: pointer, Method: "lockfile-analysis"}
}

func ID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(h[:12])
}

func NpmPURL(name, version string) string {
	if name == "" || version == "" {
		return ""
	}
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) != 2 {
			return ""
		}
		return packageurl.NewPackageURL("npm", parts[0], parts[1], version, nil, "").ToString()
	}
	return packageurl.NewPackageURL("npm", "", name, version, nil, "").ToString()
}

func DefaultNpmRegistry(raw string) bool {
	if raw == "registry.npmjs.org" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || !strings.EqualFold(u.Hostname(), "registry.npmjs.org") || u.Port() != "" && u.Port() != "443" {
		return false
	}
	return strings.Contains(u.EscapedPath(), "/-/")
}

func Integrity(raw string) []model.Hash {
	var hashes []model.Hash
	for _, token := range strings.Fields(raw) {
		parts := strings.SplitN(token, "-", 2)
		if len(parts) != 2 {
			continue
		}
		alg := strings.ToUpper(parts[0])
		switch alg {
		case "SHA-1", "SHA-256", "SHA-384", "SHA-512":
		default:
			// SRI uses sha512, sha384, etc. without the hyphen.
			switch alg {
			case "SHA1":
				alg = "SHA-1"
			case "SHA256":
				alg = "SHA-256"
			case "SHA384":
				alg = "SHA-384"
			case "SHA512":
				alg = "SHA-512"
			default:
				continue
			}
		}
		payload := strings.SplitN(parts[1], "?", 2)[0]
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			continue
		}
		wantLength := map[string]int{"SHA-1": 20, "SHA-256": 32, "SHA-384": 48, "SHA-512": 64}[alg]
		if len(decoded) != wantLength {
			continue
		}
		hashes = append(hashes, model.Hash{Alg: alg, Content: hex.EncodeToString(decoded)})
	}
	return hashes
}

func HexSHA256(raw string) []model.Hash {
	if len(raw) != 64 {
		return nil
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return nil
	}
	return []model.Hash{{Alg: "SHA-256", Content: strings.ToLower(raw)}}
}

func Finalize(doc *model.Document) {
	for _, origin := range doc.Origins {
		if origin.Kind != "vcs" || origin.SafeURL == "" {
			continue
		}
		found := false
		for _, source := range doc.Development {
			if source.Occurrence == origin.Occurrence && source.SafeURL == origin.SafeURL {
				found = true
				break
			}
		}
		if !found {
			doc.Development = append(doc.Development, model.Development{Occurrence: origin.Occurrence, SafeURL: origin.SafeURL, Status: "inferred_from_vcs_source", Evidence: origin.Evidence})
		}
	}
	for _, issue := range doc.Coverage.Issues {
		switch issue.Code {
		case "unresolved_dependency", "ambiguous_dependency", "missing_direct_dependencies", "duplicate_spec", "conditional_graph", "unsupported_lock_version", "unsupported_lock_feature", "unreachable_graph", "manifest_freshness_unverified", "target_conditions_unresolved", "transitive_graph_unavailable", "vendor_manifest_mismatch", "vendor_package_missing", "workspace_unresolved", "workspace_version_unresolved", "workspace_manifest_mismatch", "artifact_graph_partial", "multi_module_scope_root", "maven_module_unresolved", "maven_inherited_dependencies_unavailable", "maven_profiles_unresolved", "gradle_variant_union", "gradle_unidentified_component", "cargo_dep_kinds_unavailable", "duplicate_archive_entry", "source_scan_limited", "source_parse_error", "source_import_map_unavailable", "version_unresolved", "lock_tree_limited", "dependency_constraint_unverified", "dpkg_package_unhealthy":
			doc.Coverage.GraphState = "partial"
		case "missing_source", "ambiguous_source", "unsafe_or_invalid_source", "source_unresolved", "distribution_source_unavailable", "patch_metadata_invalid", "patch_unavailable", "patch_integrity_mismatch":
			doc.Coverage.OriginState = "partial"
		}
	}
	doc.Coverage.Packages = len(doc.Components)
	doc.Coverage.Edges = len(doc.Edges)
	sort.Slice(doc.Components, func(i, j int) bool { return doc.Components[i].ID < doc.Components[j].ID })
	sort.Slice(doc.Edges, func(i, j int) bool {
		a, b := doc.Edges[i], doc.Edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Condition != b.Condition {
			return a.Condition < b.Condition
		}
		return a.Evidence.Pointer < b.Evidence.Pointer
	})
	sort.Slice(doc.Origins, func(i, j int) bool {
		a, b := doc.Origins[i], doc.Origins[j]
		if a.Occurrence != b.Occurrence {
			return a.Occurrence < b.Occurrence
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.SafeURL != b.SafeURL {
			return a.SafeURL < b.SafeURL
		}
		return a.Revision < b.Revision
	})
	sort.Slice(doc.Development, func(i, j int) bool {
		a, b := doc.Development[i], doc.Development[j]
		if a.Occurrence != b.Occurrence {
			return a.Occurrence < b.Occurrence
		}
		return a.SafeURL < b.SafeURL
	})
	sort.Slice(doc.Coverage.Issues, func(i, j int) bool {
		a, b := doc.Coverage.Issues[i], doc.Coverage.Issues[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Scope < b.Scope
	})
}
