package oci

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const (
	bunBinaryPath     = "usr/local/bin/bun"
	maxBunBinaryBytes = 256 << 20
)

const bunVersionExpression = `[1-9][0-9]{0,2}\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})`

var (
	bunBannerPattern = regexp.MustCompile(`\x00Bun v(` + bunVersionExpression + `) \(Linux (arm64|x64)\)`)
	bunAgentPattern  = regexp.MustCompile(`Bun/(` + bunVersionExpression + `)\x00`)
	errBunBinaryIO   = errors.New("Bun executable I/O failure")
)

type bunBinaryState struct {
	document model.Document
	status   string
}

// inspectBunBinary spools a bounded executable to disk so even large Bun
// builds can be hashed and inspected without retaining their bytes in RAM.
func inspectBunBinary(input io.Reader, size int64, source, project string) (model.Document, error) {
	if size < 64 || size > maxBunBinaryBytes {
		return model.Document{}, errors.New("invalid Bun executable size")
	}
	file, err := os.CreateTemp("", "ravel-bun-binary-")
	if err != nil {
		return model.Document{}, fmt.Errorf("%w: %v", errBunBinaryIO, err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	hash := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(file, hash), input, size); err != nil {
		return model.Document{}, fmt.Errorf("%w: %v", errBunBinaryIO, err)
	}
	if err := guardELFMetadataReader(file, size); err != nil {
		return model.Document{}, err
	}
	return bunDocumentFromELF(file, size, hex.EncodeToString(hash.Sum(nil)), source, project)
}

func bunDocumentFromELF(reader io.ReaderAt, size int64, digest, source, project string) (document model.Document, err error) {
	defer func() {
		if recover() != nil {
			document = model.Document{}
			err = errors.New("malformed Bun ELF")
		}
	}()
	file, err := elf.NewFile(reader)
	if err != nil || file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return model.Document{}, errors.New("invalid Bun ELF")
	}
	var architecture string
	switch file.Machine {
	case elf.EM_AARCH64:
		architecture = "arm64"
	case elf.EM_X86_64:
		architecture = "x64"
	default:
		return model.Document{}, errors.New("unsupported Bun ELF architecture")
	}
	section := file.Section(".rodata")
	if section == nil || section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_ALLOC == 0 || section.Flags&(elf.SHF_WRITE|elf.SHF_COMPRESSED) != 0 || section.Offset > uint64(size) || section.Size > uint64(size)-section.Offset {
		return model.Document{}, errors.New("Bun read-only data is unavailable")
	}
	version, offset, err := bunVersionInROData(io.NewSectionReader(reader, int64(section.Offset), int64(section.Size)), int64(section.Size), architecture)
	if err != nil {
		return model.Document{}, fmt.Errorf("%w: %v", errBunBinaryIO, err)
	}
	if version == "" {
		return model.Document{}, errors.New("Bun executable version is unavailable or ambiguous")
	}
	evidence := model.Evidence{Collector: "bun-runtime-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.FormatInt(int64(section.Offset)+offset, 10), Method: "embedded-runtime-version"}
	doc := common.NewDocument(source, project, "bun-runtime", nil)
	id := "bun-runtime:" + common.ID(source+"\x00"+version)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "application", Name: "bun", Version: version, Context: "location=/" + bunBinaryPath + ";runtime=bun", Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "bun_runtime_graph_unavailable", Name: bunBinaryPath}, model.Issue{Code: "bun_runtime_origin_unavailable", Name: bunBinaryPath})
	common.Finalize(&doc)
	return doc, nil
}

// bunVersionInROData requires a CLI banner and an independently embedded
// user-agent version. The fixed overlap catches markers spanning read windows.
func bunVersionInROData(input io.Reader, size int64, architecture string) (string, int64, error) {
	const chunkSize = 64 << 10
	const overlap = 128
	buffer := make([]byte, chunkSize+overlap)
	consumed := int64(0)
	carry := 0
	bannerVersion, agentVersion := "", ""
	bannerOffset := int64(-1)
	for consumed < size {
		readSize := int(min(int64(chunkSize), size-consumed))
		if _, err := io.ReadFull(input, buffer[carry:carry+readSize]); err != nil {
			return "", -1, err
		}
		window := buffer[:carry+readSize]
		base := consumed - int64(carry)
		for _, match := range bunBannerPattern.FindAllSubmatchIndex(window, -1) {
			candidate := string(window[match[2]:match[3]])
			if string(window[match[4]:match[5]]) != architecture || bannerVersion != "" && candidate != bannerVersion {
				return "", -1, nil
			}
			bannerVersion = candidate
			if bannerOffset < 0 {
				bannerOffset = base + int64(match[2])
			}
		}
		for _, match := range bunAgentPattern.FindAllSubmatchIndex(window, -1) {
			candidate := string(window[match[2]:match[3]])
			if agentVersion != "" && candidate != agentVersion {
				return "", -1, nil
			}
			agentVersion = candidate
		}
		consumed += int64(readSize)
		carry = min(overlap, len(window))
		copy(buffer[:carry], window[len(window)-carry:])
	}
	if bannerVersion == "" || bannerVersion != agentVersion {
		return "", -1, nil
	}
	return bannerVersion, bannerOffset, nil
}
