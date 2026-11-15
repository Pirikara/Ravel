package deno

import (
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

// Index and resolve lock entries once for both local-source and verified
// remote-source imports. Peer-specific npm keys stay distinct.
func indexLockedPackages(lock lockfile) (map[string]item, map[string][]string) {
	items := map[string]item{}
	byName := map[string][]string{}
	for key, meta := range lock.JSR {
		name, version, ok := splitNameVersion(key)
		if !ok {
			continue
		}
		items["jsr:"+key] = item{ref: "deno:jsr:" + common.ID(key), name: name, version: version, deps: meta.Dependencies, kind: "jsr"}
		byName["jsr:"+name] = append(byName["jsr:"+name], "jsr:"+key)
	}
	for key, meta := range lock.NPM {
		name, version, ok := splitNameVersion(key)
		if !ok {
			continue
		}
		version = strings.SplitN(version, "_", 2)[0]
		items["npm:"+key] = item{ref: "deno:npm:" + common.ID(key), name: name, version: version, deps: meta.Dependencies, kind: "npm"}
		byName["npm:"+name] = append(byName["npm:"+name], "npm:"+key)
	}
	return items, byName
}

func resolveLockedSpec(spec string, lock lockfile, items map[string]item, byName map[string][]string) string {
	if strings.HasPrefix(spec, "http://") || strings.HasPrefix(spec, "https://") {
		if _, exists := lock.Remote[spec]; exists && safeurl.Clean(spec) != "" {
			return "remote:" + spec
		}
		return ""
	}
	kind := "npm"
	value := spec
	if strings.HasPrefix(value, "jsr:") {
		kind = "jsr"
		value = strings.TrimPrefix(value, "jsr:")
	} else {
		value = strings.TrimPrefix(value, "npm:")
	}
	name, version, withVersion := splitNameVersion(value)
	if !withVersion {
		name = barePackageName(value)
	}
	if pinned, ok := lock.Specifiers[spec]; ok {
		version = pinned
		withVersion = true
	} else if withVersion {
		if slash := strings.IndexByte(version, '/'); slash >= 0 {
			version = version[:slash]
			if pinned, ok := lock.Specifiers[kind+":"+name+"@"+version]; ok {
				version = pinned
			}
		}
	}
	if withVersion {
		key := kind + ":" + name + "@" + version
		if _, ok := items[key]; ok {
			return key
		}
		var matching string
		for _, candidate := range byName[kind+":"+name] {
			if strings.HasPrefix(candidate, key+"_") {
				if matching != "" {
					return ""
				}
				matching = candidate
			}
		}
		return matching
	}
	if matches := byName[kind+":"+name]; len(matches) == 1 {
		return matches[0]
	}
	return ""
}

func addLockedPackage(doc *model.Document, file string, data []byte, lock lockfile, key string, entry item) {
	meta := packageEntry{}
	if entry.kind == "jsr" {
		meta = lock.JSR[strings.TrimPrefix(key, "jsr:")]
	} else {
		meta = lock.NPM[strings.TrimPrefix(key, "npm:")]
	}
	ev := common.Evidence(file, "deno-lock", "/"+entry.kind, data)
	component := model.Component{ID: entry.ref, Kind: "package", Name: entry.name, Version: entry.version, Evidence: []model.Evidence{ev}}
	if entry.kind == "jsr" {
		component.Hashes = common.HexSHA256(meta.Integrity)
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: entry.ref, Kind: "registry_identity", SafeURL: "https://jsr.io", Status: "inferred", Evidence: ev})
	} else {
		component.Hashes = common.Integrity(meta.Integrity)
		component.PURL = common.NpmPURL(entry.name, entry.version)
		component.PURLBasis = "ecosystem_inferred"
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "source_unresolved", Name: entry.name})
	}
	doc.Components = append(doc.Components, component)
}
