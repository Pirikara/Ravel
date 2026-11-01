package oci

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const (
	redisBinaryPath     = "usr/local/bin/redis-server"
	maxRedisBinaryBytes = 32 << 20
)

const redisVersionExpression = `[1-9][0-9]{0,2}\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})`

var (
	redisInfoVersionPattern  = regexp.MustCompile(`\x00(` + redisVersionExpression + `)\x00\x00# Server\r\nredis_version:%s\r\n`)
	redisBuildVersionPattern = regexp.MustCompile(`\x00(` + redisVersionExpression + `)buildkitsandbox-[0-9]{1,32}\x00`)
)

type redisBinaryState struct {
	document model.Document
	status   string
}

// inspectRedisBinary identifies a source-installed Redis server from two
// agreeing version-bearing strings in the executable's read-only ELF data.
func inspectRedisBinary(data []byte, source, project, filename string) (document model.Document, err error) {
	if filename != redisBinaryPath || len(data) == 0 || len(data) > maxRedisBinaryBytes {
		return model.Document{}, errors.New("invalid Redis executable path or size")
	}
	if err := guardELFMetadata(data); err != nil {
		return model.Document{}, err
	}
	defer func() {
		if recover() != nil {
			document = model.Document{}
			err = errors.New("malformed Redis ELF")
		}
	}()
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return model.Document{}, errors.New("invalid Redis ELF")
	}
	section := file.Section(".rodata")
	if section == nil || section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_ALLOC == 0 || section.Flags&(elf.SHF_WRITE|elf.SHF_COMPRESSED) != 0 || section.Offset > uint64(len(data)) || section.Size > uint64(len(data))-section.Offset {
		return model.Document{}, errors.New("Redis read-only data is unavailable")
	}
	version, offset, ok := redisVersionInROData(data[section.Offset : section.Offset+section.Size])
	if !ok {
		return model.Document{}, errors.New("Redis executable version is unavailable or ambiguous")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "redis-runtime-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.FormatUint(section.Offset+uint64(offset), 10), Method: "embedded-runtime-version"}
	doc := common.NewDocument(source, project, "redis-runtime", nil)
	id := "redis-runtime:" + common.ID(source+"\x00"+version)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "application", Name: "redis", Version: version, Context: "location=/" + redisBinaryPath + ";runtime=redis", Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "redis_runtime_graph_unavailable", Name: filename}, model.Issue{Code: "redis_runtime_origin_unavailable", Name: filename})
	common.Finalize(&doc)
	return doc, nil
}

func redisVersionInROData(data []byte) (string, int, bool) {
	if !bytes.Contains(data, []byte("\x00Redis server %s\n\x00")) {
		return "", -1, false
	}
	infoMatches := redisInfoVersionPattern.FindAllSubmatchIndex(data, 9)
	buildMatches := redisBuildVersionPattern.FindAllSubmatchIndex(data, 9)
	if len(infoMatches) == 0 || len(infoMatches) > 8 || len(buildMatches) == 0 || len(buildMatches) > 8 {
		return "", -1, false
	}
	version, offset := "", -1
	for _, match := range infoMatches {
		candidate := string(data[match[2]:match[3]])
		if version != "" && version != candidate {
			return "", -1, false
		}
		version, offset = candidate, match[2]
	}
	for _, match := range buildMatches {
		if string(data[match[2]:match[3]]) != version {
			return "", -1, false
		}
	}
	return version, offset, true
}
