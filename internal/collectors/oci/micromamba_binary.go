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
	micromambaBinaryPath     = "usr/bin/micromamba"
	maxMicromambaBinaryBytes = 64 << 20
)

var micromambaAgentPattern = regexp.MustCompile(`\x00mamba/([1-9][0-9]{0,2}\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2}))\x00`)

type micromambaBinaryState struct {
	document model.Document
	status   string
}

// inspectMicromambaBinary checks the final ELF without executing image code.
// The libmamba user agent and two adjacent build-version strings must agree.
func inspectMicromambaBinary(data []byte, source, project, architecture string) (document model.Document, err error) {
	if len(data) < 64 || len(data) > maxMicromambaBinaryBytes {
		return model.Document{}, errors.New("invalid micromamba executable size")
	}
	if err := guardELFMetadata(data); err != nil {
		return model.Document{}, err
	}
	defer func() {
		if recover() != nil {
			document = model.Document{}
			err = errors.New("malformed micromamba ELF")
		}
	}()
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return model.Document{}, errors.New("invalid micromamba ELF")
	}
	if architecture != "arm64" && architecture != "amd64" || architecture == "arm64" && file.Machine != elf.EM_AARCH64 || architecture == "amd64" && file.Machine != elf.EM_X86_64 {
		return model.Document{}, errors.New("micromamba ELF architecture does not match image")
	}
	section := file.Section(".rodata")
	if section == nil || section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_ALLOC == 0 || section.Flags&(elf.SHF_WRITE|elf.SHF_COMPRESSED) != 0 || section.Offset > uint64(len(data)) || section.Size > uint64(len(data))-section.Offset {
		return model.Document{}, errors.New("micromamba read-only data is unavailable")
	}
	rodata := data[section.Offset : section.Offset+section.Size]
	version, offset, ok := micromambaVersionInROData(rodata)
	if !ok {
		return model.Document{}, errors.New("micromamba executable version is unavailable or ambiguous")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "micromamba-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.FormatUint(section.Offset+uint64(offset), 10), Method: "embedded-runtime-version"}
	doc := common.NewDocument(source, project, "micromamba-runtime", nil)
	id := "micromamba-runtime:" + common.ID(source+"\x00"+version)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "application", Name: "micromamba", Version: version, Context: "location=/" + micromambaBinaryPath + ";runtime=micromamba", Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "micromamba_runtime_graph_unavailable", Name: micromambaBinaryPath}, model.Issue{Code: "micromamba_runtime_origin_unavailable", Name: micromambaBinaryPath})
	common.Finalize(&doc)
	return doc, nil
}

func micromambaVersionInROData(data []byte) (string, int, bool) {
	if !bytes.Contains(data, []byte("\x00Install specific micromamba version\x00")) {
		return "", -1, false
	}
	matches := micromambaAgentPattern.FindAllSubmatchIndex(data, 3)
	if len(matches) != 1 {
		return "", -1, false
	}
	version := string(data[matches[0][2]:matches[0][3]])
	// The build embeds both CLI and libmamba versions as adjacent strings.
	adjacent := append(append([]byte("\x00"), []byte(version)...), 0)
	for padding := 0; padding <= 7; padding++ {
		candidate := append(append(append([]byte{}, adjacent...), bytes.Repeat([]byte{0}, padding)...), []byte(version)...)
		candidate = append(candidate, 0)
		if bytes.Contains(data, candidate) {
			return version, matches[0][2], true
		}
	}
	return "", -1, false
}
