package oci

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"strconv"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const (
	postgresBinaryPath     = "usr/local/bin/postgres"
	maxPostgresBinaryBytes = 32 << 20
)

var postgresVersionPattern = regexp.MustCompile(`^[1-9][0-9]{0,2}(?:\.(?:0|[1-9][0-9]{0,2})){1,2}(?:(?:alpha|beta|rc)[1-9][0-9]?)?$`)

type postgresBinaryState struct {
	document model.Document
	status   string
}

// inspectPostgresBinary identifies a self-installed PostgreSQL server by two
// agreeing version strings in the ELF read-only data. Package-managed server
// paths are left to the installed package database.
func inspectPostgresBinary(data []byte, source, project, filename string) (document model.Document, err error) {
	if filename != postgresBinaryPath || len(data) == 0 || len(data) > maxPostgresBinaryBytes {
		return model.Document{}, errors.New("invalid PostgreSQL executable path or size")
	}
	if err := guardELFMetadata(data); err != nil {
		return model.Document{}, err
	}
	defer func() {
		if recover() != nil {
			document = model.Document{}
			err = errors.New("malformed PostgreSQL ELF")
		}
	}()
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return model.Document{}, errors.New("invalid PostgreSQL ELF")
	}
	section := file.Section(".rodata")
	if section == nil || section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_ALLOC == 0 || section.Flags&(elf.SHF_WRITE|elf.SHF_COMPRESSED) != 0 || section.Offset > uint64(len(data)) || section.Size > uint64(len(data))-section.Offset {
		return model.Document{}, errors.New("PostgreSQL read-only data is unavailable")
	}
	version, offset, ok := postgresVersionInROData(data[section.Offset : section.Offset+section.Size])
	if !ok {
		return model.Document{}, errors.New("PostgreSQL executable version is unavailable or ambiguous")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "postgres-runtime-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.FormatUint(section.Offset+uint64(offset), 10), Method: "embedded-runtime-version"}
	doc := common.NewDocument(source, project, "postgres-runtime", nil)
	id := "postgres-runtime:" + common.ID(source+"\x00"+version)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "application", Name: "postgresql", Version: version, Context: "location=/" + path.Clean(filename) + ";runtime=postgresql", Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "postgres_runtime_graph_unavailable", Name: filename}, model.Issue{Code: "postgres_runtime_origin_unavailable", Name: filename})
	common.Finalize(&doc)
	return doc, nil
}

func postgresVersionInROData(data []byte) (string, int, bool) {
	const marker = "postgres (PostgreSQL) "
	version := ""
	offset := -1
	for position := 0; position < len(data); {
		index := bytes.Index(data[position:], []byte(marker))
		if index < 0 {
			break
		}
		start := position + index
		position = start + len(marker)
		if start == 0 || data[start-1] != 0 {
			continue
		}
		lineEnd := bytes.IndexByte(data[position:], '\n')
		if lineEnd < 0 || lineEnd > 128 || position+lineEnd+1 >= len(data) || data[position+lineEnd+1] != 0 {
			continue
		}
		line := string(data[position : position+lineEnd])
		candidate, suffix, found := strings.Cut(line, " ")
		if !found {
			candidate = line
		}
		if !postgresVersionPattern.MatchString(candidate) || found && (len(suffix) < 3 || suffix[0] != '(' || suffix[len(suffix)-1] != ')') {
			continue
		}
		buildMarker := []byte("\x00PostgreSQL " + line + " on ")
		if !bytes.Contains(data, buildMarker) {
			continue
		}
		if version != "" && version != candidate {
			return "", -1, false
		}
		version = candidate
		offset = start
	}
	return version, offset, version != ""
}
