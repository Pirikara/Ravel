package oci

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const (
	denoBinaryPath     = "bin/deno"
	maxDenoBinaryBytes = 256 << 20
)

const denoVersionExpression = `[1-9][0-9]{0,2}\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})`

var (
	denoAgentPattern = regexp.MustCompile(`Deno/(` + denoVersionExpression + `)`)
	errDenoBinaryIO  = errors.New("Deno executable I/O failure")
)

type denoBinaryState struct {
	document model.Document
	status   string
}

// inspectDenoBinary keeps only a small read window in memory while hashing
// and inspecting the executable. It never runs code from the image.
func inspectDenoBinary(input io.Reader, size int64, source, project, architecture string) (model.Document, error) {
	if size < 64 || size > maxDenoBinaryBytes {
		return model.Document{}, errors.New("invalid Deno executable size")
	}
	file, err := os.CreateTemp("", "ravel-deno-binary-")
	if err != nil {
		return model.Document{}, fmt.Errorf("%w: %v", errDenoBinaryIO, err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	hash := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(file, hash), input, size); err != nil {
		return model.Document{}, fmt.Errorf("%w: %v", errDenoBinaryIO, err)
	}
	if err := guardELFMetadataReader(file, size); err != nil {
		return model.Document{}, err
	}
	return denoDocumentFromELF(file, size, hex.EncodeToString(hash.Sum(nil)), source, project, architecture)
}

func denoDocumentFromELF(reader io.ReaderAt, size int64, digest, source, project, architecture string) (document model.Document, err error) {
	defer func() {
		if recover() != nil {
			document = model.Document{}
			err = errors.New("malformed Deno ELF")
		}
	}()
	file, err := elf.NewFile(reader)
	if err != nil || file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return model.Document{}, errors.New("invalid Deno ELF")
	}
	if architecture != "arm64" && architecture != "amd64" || architecture == "arm64" && file.Machine != elf.EM_AARCH64 || architecture == "amd64" && file.Machine != elf.EM_X86_64 {
		return model.Document{}, errors.New("Deno ELF architecture does not match image")
	}
	section := file.Section(".rodata")
	if section == nil || section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_ALLOC == 0 || section.Flags&(elf.SHF_WRITE|elf.SHF_COMPRESSED) != 0 || section.Offset > uint64(size) || section.Size > uint64(size)-section.Offset {
		return model.Document{}, errors.New("Deno read-only data is unavailable")
	}
	version, offset, err := denoVersionInROData(io.NewSectionReader(reader, int64(section.Offset), int64(section.Size)), int64(section.Size))
	if err != nil {
		return model.Document{}, fmt.Errorf("%w: %v", errDenoBinaryIO, err)
	}
	if version == "" {
		return model.Document{}, errors.New("Deno executable version is unavailable or ambiguous")
	}
	evidence := model.Evidence{Collector: "deno-runtime-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.FormatInt(int64(section.Offset)+offset, 10), Method: "embedded-runtime-version"}
	doc := common.NewDocument(source, project, "deno-runtime", nil)
	id := "deno-runtime:" + common.ID(source+"\x00"+version)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "application", Name: "deno", Version: version, Context: "location=/" + denoBinaryPath + ";runtime=deno", Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "deno_runtime_graph_unavailable", Name: denoBinaryPath}, model.Issue{Code: "deno_runtime_origin_unavailable", Name: denoBinaryPath})
	common.Finalize(&doc)
	return doc, nil
}

// denoVersionInROData looks for the adjacent release and user-agent versions
// observed in official Deno builds. Requiring both forms and the same revision
// avoids confusing a bundled dependency's Deno user-agent with the runtime.
func denoVersionInROData(input io.Reader, size int64) (string, int64, error) {
	const chunkSize = 64 << 10
	const overlap = 256
	buffer := make([]byte, chunkSize+overlap)
	consumed := int64(0)
	carry := 0
	version := ""
	offset := int64(-1)
	for consumed < size {
		readSize := int(min(int64(chunkSize), size-consumed))
		if _, err := io.ReadFull(input, buffer[carry:carry+readSize]); err != nil {
			return "", -1, err
		}
		window := buffer[:carry+readSize]
		base := consumed - int64(carry)
		for _, match := range denoAgentPattern.FindAllSubmatchIndex(window, -1) {
			candidate := string(window[match[2]:match[3]])
			// These four adjacent strings are the release version, the
			// revision-qualified release version, and their Deno/ forms.
			// The revision is seven lowercase hexadecimal characters.
			const revisionSize = 7
			prefixSize := len(candidate)*2 + 1 + revisionSize
			suffix := []byte("Deno/" + candidate + "+")
			if match[0] < prefixSize || match[1]+len(suffix)+revisionSize > len(window) || !bytes.Equal(window[match[1]:match[1]+len(suffix)], suffix) {
				continue
			}
			revision := window[match[1]+len(suffix) : match[1]+len(suffix)+revisionSize]
			validRevision := true
			for _, char := range revision {
				if char < '0' || char > '9' && (char < 'a' || char > 'f') {
					validRevision = false
					break
				}
			}
			if !validRevision || !bytes.Equal(window[match[0]-prefixSize:match[0]], []byte(candidate+candidate+"+"+string(revision))) {
				continue
			}
			if version != "" && candidate != version {
				return "", -1, nil
			}
			version = candidate
			if offset < 0 {
				offset = base + int64(match[2])
			}
		}
		consumed += int64(readSize)
		carry = min(overlap, len(window))
		copy(buffer[:carry], window[len(window)-carry:])
	}
	return version, offset, nil
}
