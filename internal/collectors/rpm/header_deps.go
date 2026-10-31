package rpm

import (
	"bytes"
	"encoding/binary"
	"strconv"

	"github.com/anchore/go-rpmdb/pkg/bdb"
	dbi "github.com/anchore/go-rpmdb/pkg/db"
	"github.com/anchore/go-rpmdb/pkg/ndb"
	"github.com/anchore/go-rpmdb/pkg/sqlite3"
)

// RPM stores dependency names, version strings, and sense flags in parallel
// header arrays. go-rpmdb exposes only the names, so read these few tags from
// the same database bytes before making any definite dependency claims.
// Header layout: https://rpm.org/docs/4.20.x/manual/format_header.html
// Dependency tags: https://rpm.org/docs/4.20.x/manual/tags.html
const (
	rpmTagName           = 1000
	rpmTagVersion        = 1001
	rpmTagRelease        = 1002
	rpmTagEpoch          = 1003
	rpmTagArch           = 1022
	rpmTagProvideName    = 1047
	rpmTagRequireFlags   = 1048
	rpmTagRequireName    = 1049
	rpmTagRequireVersion = 1050
	rpmTagProvideFlags   = 1112
	rpmTagProvideVersion = 1113
	rpmTypeInt32         = 4
	rpmTypeString        = 6
	rpmTypeStringArray   = 8
	rpmSenseLess         = 1 << 1
	rpmSenseGreater      = 1 << 2
	rpmSenseEqual        = 1 << 3
	rpmSenseMask         = rpmSenseLess | rpmSenseGreater | rpmSenseEqual
)

type headerDependency struct {
	name, version string
	flags         uint32
}

type headerDependencies struct {
	provides, requires []headerDependency
}

type rpmTag struct {
	typ, offset, count uint32
}

// readDependencyHeaders uses go-rpmdb's format readers to obtain the package
// header blobs. If any header cannot be associated with its package exactly,
// the caller retains the conditional edges from the public package view.
func readDependencyHeaders(path string, data []byte) map[string]headerDependencies {
	var database dbi.RpmDBInterface
	var err error
	switch {
	case bytes.HasPrefix(data, sqlite3.SQLite3_HeaderMagic):
		database, err = sqlite3.Open(path)
	case len(data) >= 4 && binary.LittleEndian.Uint32(data) == ndb.NDB_HeaderMagic:
		database, err = ndb.Open(path)
	default:
		database, err = bdb.Open(path)
	}
	if err != nil {
		return nil
	}
	defer database.Close()

	result := map[string]headerDependencies{}
	ambiguous := map[string]bool{}
	failed := false
	for entry := range database.Read() {
		if entry.Err != nil || len(result) >= maxPackages {
			failed = true
			continue // Drain the reader's channel before closing its database.
		}
		key, dependencies, ok := parseDependencyHeader(entry.Value)
		if !ok {
			continue // Only this package retains conditional dependency edges.
		}
		if _, duplicate := result[key]; duplicate || ambiguous[key] {
			delete(result, key)
			ambiguous[key] = true
			continue
		}
		result[key] = dependencies
	}
	if failed {
		return nil
	}
	return result
}

func parseDependencyHeader(blob []byte) (string, headerDependencies, bool) {
	if len(blob) < 8 {
		return "", headerDependencies{}, false
	}
	indexCount := uint64(binary.BigEndian.Uint32(blob[0:4]))
	dataLength := uint64(binary.BigEndian.Uint32(blob[4:8]))
	if indexCount == 0 || indexCount > 65535 || 8+16*indexCount+dataLength > uint64(len(blob)) {
		return "", headerDependencies{}, false
	}
	dataStart := 8 + 16*int(indexCount)
	values := blob[dataStart : dataStart+int(dataLength)]
	tags := map[uint32]rpmTag{}
	for i := 0; i < int(indexCount); i++ {
		offset := 8 + 16*i
		tag := binary.BigEndian.Uint32(blob[offset:])
		if !rpmDependencyTag(tag) {
			continue
		}
		if _, duplicate := tags[tag]; duplicate {
			return "", headerDependencies{}, false
		}
		tags[tag] = rpmTag{
			typ:    binary.BigEndian.Uint32(blob[offset+4:]),
			offset: binary.BigEndian.Uint32(blob[offset+8:]),
			count:  binary.BigEndian.Uint32(blob[offset+12:]),
		}
	}
	name, ok := rpmHeaderString(values, tags[rpmTagName])
	if !ok || name == "" {
		return "", headerDependencies{}, false
	}
	version, ok := rpmHeaderString(values, tags[rpmTagVersion])
	if !ok || version == "" {
		return "", headerDependencies{}, false
	}
	release, ok := rpmHeaderString(values, tags[rpmTagRelease])
	if !ok || release == "" {
		return "", headerDependencies{}, false
	}
	arch, ok := rpmHeaderString(values, tags[rpmTagArch])
	if !ok && name != "gpg-pubkey" {
		return "", headerDependencies{}, false
	}
	epoch := uint32(0)
	if tag, present := tags[rpmTagEpoch]; present {
		value, valid := rpmHeaderInts(values, tag)
		if !valid || len(value) != 1 || value[0] > 1<<31-1 {
			return "", headerDependencies{}, false
		}
		epoch = value[0]
	}
	key := name + "\x00" + strconv.FormatUint(uint64(epoch), 10) + ":" + version + "-" + release + "\x00" + arch
	provides, ok := rpmHeaderDependencies(values, tags, rpmTagProvideName, rpmTagProvideVersion, rpmTagProvideFlags)
	if !ok {
		return "", headerDependencies{}, false
	}
	requires, ok := rpmHeaderDependencies(values, tags, rpmTagRequireName, rpmTagRequireVersion, rpmTagRequireFlags)
	if !ok {
		return "", headerDependencies{}, false
	}
	return key, headerDependencies{provides: provides, requires: requires}, true
}

func rpmDependencyTag(tag uint32) bool {
	switch tag {
	case rpmTagName, rpmTagVersion, rpmTagRelease, rpmTagEpoch, rpmTagArch,
		rpmTagProvideName, rpmTagProvideVersion, rpmTagProvideFlags,
		rpmTagRequireName, rpmTagRequireVersion, rpmTagRequireFlags:
		return true
	}
	return false
}

func rpmHeaderString(data []byte, tag rpmTag) (string, bool) {
	if tag.typ != rpmTypeString || tag.count != 1 || tag.offset >= uint32(len(data)) {
		return "", false
	}
	value := data[tag.offset:]
	end := bytes.IndexByte(value, 0)
	if end < 0 || end > 4096 {
		return "", false
	}
	return string(value[:end]), true
}

func rpmHeaderStrings(data []byte, tag rpmTag) ([]string, bool) {
	if tag.typ != rpmTypeStringArray || tag.count > maxRequirements || tag.offset > uint32(len(data)) {
		return nil, false
	}
	remaining := data[tag.offset:]
	result := make([]string, 0, tag.count)
	for i := uint32(0); i < tag.count; i++ {
		end := bytes.IndexByte(remaining, 0)
		if end < 0 || end > 4096 {
			return nil, false
		}
		result = append(result, string(remaining[:end]))
		remaining = remaining[end+1:]
	}
	return result, true
}

func rpmHeaderInts(data []byte, tag rpmTag) ([]uint32, bool) {
	if tag.typ != rpmTypeInt32 || tag.count > maxRequirements || tag.offset%4 != 0 || uint64(tag.offset)+4*uint64(tag.count) > uint64(len(data)) {
		return nil, false
	}
	result := make([]uint32, tag.count)
	for i := range result {
		result[i] = binary.BigEndian.Uint32(data[int(tag.offset)+4*i:])
	}
	return result, true
}

func rpmHeaderDependencies(data []byte, tags map[uint32]rpmTag, nameTag, versionTag, flagsTag uint32) ([]headerDependency, bool) {
	namesTag, present := tags[nameTag]
	if !present {
		return nil, true
	}
	versionsTag, hasVersions := tags[versionTag]
	flagsValue, hasFlags := tags[flagsTag]
	if !hasVersions || !hasFlags {
		return nil, false
	}
	names, ok := rpmHeaderStrings(data, namesTag)
	if !ok {
		return nil, false
	}
	versions, ok := rpmHeaderStrings(data, versionsTag)
	if !ok || len(versions) != len(names) {
		return nil, false
	}
	flags, ok := rpmHeaderInts(data, flagsValue)
	if !ok || len(flags) != len(names) {
		return nil, false
	}
	result := make([]headerDependency, len(names))
	for i := range names {
		result[i] = headerDependency{name: names[i], version: versions[i], flags: flags[i]}
	}
	return result, true
}
