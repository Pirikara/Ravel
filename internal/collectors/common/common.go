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

func GoModulePURL(path, version string) string {
	if path == "" || version == "" || path != strings.ToLower(path) {
		return ""
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return ""
	}
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return "pkg:golang/" + strings.Join(parts, "/") + "@" + url.PathEscape(version)
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
		case "dotnet_standalone_assembly_graph_unavailable":
			doc.Coverage.GraphState = "partial"
		case "dotnet_standalone_assembly_origin_unavailable":
			doc.Coverage.OriginState = "partial"
		case "dotnet_standalone_assembly_identity_unverified":
			doc.Coverage.GraphState = "partial"
			doc.Coverage.OriginState = "partial"
		case "unresolved_dependency", "ambiguous_dependency", "missing_direct_dependencies", "duplicate_spec", "conditional_graph", "unsupported_lock_version", "unsupported_lock_feature", "unreachable_graph", "manifest_freshness_unverified", "target_conditions_unresolved", "transitive_graph_unavailable", "vendor_manifest_mismatch", "workspace_unresolved", "workspace_version_unresolved", "workspace_manifest_mismatch", "artifact_graph_partial", "multi_module_scope_root", "maven_module_unresolved", "maven_inherited_dependencies_unavailable", "maven_profiles_unresolved", "gradle_variant_union", "gradle_unidentified_component", "cargo_dep_kinds_unavailable", "duplicate_archive_entry", "source_scan_limited", "source_parse_error", "source_import_map_unavailable", "version_unresolved", "lock_tree_limited", "dependency_constraint_unverified", "dpkg_package_unhealthy", "apk_package_unhealthy", "apk_dependency_unparsed", "image_language_packages_unscanned", "declared_dependencies_unresolved", "python_requirement_unparsed", "requested_extra_graph_unavailable", "conditional_dependency_unresolved", "node_dependency_manifest_invalid", "node_resolution_unverified", "node_package_alias_unverified", "node_dependency_specifier_unverified", "rpm_requirement_unparsed", "rpm_file_requirement_unresolved", "rpm_dependency_flags_unavailable", "go_binary_graph_unavailable", "go_binary_toolchain_unparsed", "go_binary_module_unparsed", "go_binary_local_replacement_unresolved", "pip_vendor_graph_unavailable", "pip_vendor_parent_unresolved", "python_runtime_graph_unavailable", "node_runtime_graph_unavailable", "postgres_runtime_graph_unavailable", "redis_runtime_graph_unavailable", "ruby_installed_activation_unresolved", "ruby_installed_dependency_unparsed", "ruby_installed_dependency_scan_limited", "ruby_installed_dependency_constraint_unverified", "ruby_installed_dependency_unresolved", "ruby_installed_dependency_ambiguous", "ruby_runtime_graph_unavailable":
			doc.Coverage.GraphState = "partial"
		case "rpm_file_inventory_unavailable", "rpm_file_inventory_limited", "rpm_boolean_guard_unverified", "python_egg_requirements_unscanned", "composer_installed_files_unverified", "composer_installed_requirement_invalid", "composer_installed_provider_invalid", "composer_installed_virtual_provider_unverified", "composer_package_manifest_invalid", "composer_package_manifest_oversized", "composer_package_manifest_link_unresolved", "composer_package_manifest_unsupported", "composer_package_manifest_scan_limited", "composer_package_manifest_mismatch", "dotnet_runtime_assets_unverified", "dotnet_manifest_only_library", "dotnet_non_runtime_library_omitted", "dotnet_library_type_unhandled", "dotnet_dependency_invalid", "dotnet_root_project_unresolved", "dotnet_runtimepack_identity_unverified", "dotnet_runtime_assembly_identity_unverified", "dotnet_runtime_assembly_rid_unselected", "dotnet_runtime_assembly_ambiguous", "dotnet_runtime_assembly_invalid", "dotnet_runtime_assembly_oversized", "dotnet_runtime_assembly_link_unresolved", "dotnet_runtime_assembly_unsupported", "dotnet_runtime_assembly_scan_limited":
			doc.Coverage.GraphState = "partial"
		case "python_installed_metadata_invalid", "composer_installed_metadata_invalid", "composer_installed_metadata_oversized", "composer_installed_metadata_link_unresolved", "composer_installed_metadata_unsupported", "dotnet_deps_metadata_invalid", "dotnet_deps_metadata_oversized", "dotnet_deps_metadata_link_unresolved", "dotnet_deps_metadata_unsupported", "node_installed_metadata_invalid", "java_installed_archive_invalid", "java_installed_archive_oversized", "java_installed_archive_link_unresolved", "go_binary_invalid", "go_binary_oversized", "go_binary_scan_limited", "pip_vendor_manifest_invalid", "python_runtime_invalid", "python_runtime_oversized", "python_runtime_scan_limited", "node_runtime_invalid", "node_runtime_oversized", "node_runtime_version_unavailable", "node_runtime_version_mismatch", "node_runtime_header_invalid", "postgres_runtime_invalid", "postgres_runtime_oversized", "redis_runtime_invalid", "redis_runtime_oversized", "ruby_installed_spec_invalid", "ruby_runtime_invalid", "ruby_runtime_oversized", "ruby_runtime_scan_limited":
			doc.Coverage.GraphState = "partial"
			doc.Coverage.OriginState = "partial"
		case "missing_source", "ambiguous_source", "unsafe_or_invalid_source", "source_unresolved", "distribution_source_unavailable", "dotnet_package_hash_invalid", "patch_metadata_invalid", "patch_unavailable", "patch_integrity_mismatch", "go_binary_origin_unavailable", "pip_vendor_origin_unavailable", "python_runtime_origin_unavailable", "node_runtime_origin_unavailable", "postgres_runtime_origin_unavailable", "redis_runtime_origin_unavailable", "ruby_installed_origin_unavailable", "ruby_runtime_origin_unavailable":
			doc.Coverage.OriginState = "partial"
		case "bun_runtime_graph_unavailable":
			doc.Coverage.GraphState = "partial"
		case "bun_runtime_invalid", "bun_runtime_oversized":
			doc.Coverage.GraphState = "partial"
			doc.Coverage.OriginState = "partial"
		case "bun_runtime_origin_unavailable":
			doc.Coverage.OriginState = "partial"
		case "setuptools_vendor_metadata_invalid", "setuptools_vendor_parent_unresolved":
			doc.Coverage.GraphState = "partial"
			doc.Coverage.OriginState = "partial"
		case "setuptools_vendor_graph_unavailable":
			doc.Coverage.GraphState = "partial"
		case "setuptools_vendor_origin_unavailable":
			doc.Coverage.OriginState = "partial"
		case "rust_auditable_invalid", "rust_auditable_legacy_ambiguous", "rust_auditable_scan_limited":
			doc.Coverage.GraphState = "partial"
			doc.Coverage.OriginState = "partial"
		case "rust_auditable_graph_declared":
			doc.Coverage.GraphState = "partial"
		case "rust_auditable_origin_unverified":
			doc.Coverage.OriginState = "partial"
		case "node_system_owner_unresolved", "node_system_owner_ambiguous", "node_system_ownership_scan_limited", "ruby_platform_config_invalid", "ruby_platform_config_oversized":
			doc.Coverage.GraphState = "partial"
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
