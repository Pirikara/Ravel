package oci

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const (
	memcachedBinaryPath     = "usr/local/bin/memcached"
	maxMemcachedBinaryBytes = 32 << 20
)

const memcachedVersionExpression = `[1-9][0-9]{0,2}\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})`

var (
	memcachedFlagVersionPattern  = regexp.MustCompile(`\x00memcached (` + memcachedVersionExpression + `)\x00`)
	memcachedUsageVersionPattern = regexp.MustCompile(`\x00memcached (` + memcachedVersionExpression + `)\n\x00`)
	memcachedWireVersionPattern  = regexp.MustCompile(`\x00VERSION (` + memcachedVersionExpression + `)\x00`)
)

type memcachedBinaryState struct {
	document model.Document
	status   string
}

// inspectMemcachedBinary requires three agreeing version-bearing strings in
// the final server executable; no code from the image is run by the scanner.
func inspectMemcachedBinary(data []byte, source, project, architecture string) (document model.Document, err error) {
	if len(data) < 64 || len(data) > maxMemcachedBinaryBytes {
		return model.Document{}, errors.New("invalid Memcached executable size")
	}
	if err := guardELFMetadata(data); err != nil {
		return model.Document{}, err
	}
	defer func() {
		if recover() != nil {
			document = model.Document{}
			err = errors.New("malformed Memcached ELF")
		}
	}()
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return model.Document{}, errors.New("invalid Memcached ELF")
	}
	if architecture != "arm64" && architecture != "amd64" || architecture == "arm64" && file.Machine != elf.EM_AARCH64 || architecture == "amd64" && file.Machine != elf.EM_X86_64 {
		return model.Document{}, errors.New("Memcached ELF architecture does not match image")
	}
	section := file.Section(".rodata")
	if section == nil || section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_ALLOC == 0 || section.Flags&(elf.SHF_WRITE|elf.SHF_COMPRESSED) != 0 || section.Offset > uint64(len(data)) || section.Size > uint64(len(data))-section.Offset {
		return model.Document{}, errors.New("Memcached read-only data is unavailable")
	}
	version, offset, ok := memcachedVersionInROData(data[section.Offset : section.Offset+section.Size])
	if !ok {
		return model.Document{}, errors.New("Memcached executable version is unavailable or ambiguous")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "memcached-server-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.FormatUint(section.Offset+uint64(offset), 10), Method: "embedded-server-version"}
	doc := common.NewDocument(source, project, "memcached-server", nil)
	id := "memcached-server:" + common.ID(source+"\x00"+version)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "application", Name: "memcached", Version: version, Context: "location=/" + memcachedBinaryPath + ";server=memcached", Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "memcached_server_graph_unavailable", Name: memcachedBinaryPath}, model.Issue{Code: "memcached_server_origin_unavailable", Name: memcachedBinaryPath})
	common.Finalize(&doc)
	return doc, nil
}

func memcachedVersionInROData(data []byte) (string, int, bool) {
	patterns := []*regexp.Regexp{memcachedFlagVersionPattern, memcachedUsageVersionPattern, memcachedWireVersionPattern}
	version, offset := "", -1
	for _, pattern := range patterns {
		matches := pattern.FindAllSubmatchIndex(data, 9)
		if len(matches) == 0 || len(matches) > 8 {
			return "", -1, false
		}
		for _, match := range matches {
			candidate := string(data[match[2]:match[3]])
			if version != "" && candidate != version {
				return "", -1, false
			}
			version = candidate
			if offset < 0 {
				offset = match[2]
			}
		}
	}
	return version, offset, true
}
