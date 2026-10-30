package oci

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const (
	nodeRuntimeBinaryPath = "usr/local/bin/node"
	nodeRuntimeHeaderPath = "usr/local/include/node/node_version.h"
	maxNodeRuntimeBytes   = 256 << 20
	maxNodeHeaderBytes    = 64 << 10
)

var nodeEmbeddedVersion = regexp.MustCompile(`\x00node\.js/v([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\x00`)
var nodeHeaderVersion = regexp.MustCompile(`(?m)^#define[ \t]+NODE_(MAJOR|MINOR|PATCH)_VERSION[ \t]+([^ \t\r\n]+)[ \t]*\r?$`)
var nodeHeaderRelease = regexp.MustCompile(`(?m)^#define[ \t]+NODE_VERSION_IS_RELEASE[ \t]+([^ \t\r\n]+)[ \t]*\r?$`)

type nodeRuntimeBinaryState struct {
	version  string
	digest   string
	evidence model.Evidence
	status   string
}

type nodeRuntimeHeaderState struct {
	version  string
	evidence model.Evidence
	status   string
}

// inspectNodeRuntimeBinary scans the ELF entry with a small window. The
// embedded marker is tied to a regular ELF executable at Node's conventional
// self-installed path, never executed.
func inspectNodeRuntimeBinary(input io.Reader, size int64, source string) (nodeRuntimeBinaryState, error) {
	if size < 64 || size > maxNodeRuntimeBytes {
		return nodeRuntimeBinaryState{status: "invalid"}, nil
	}
	var header [64]byte
	if _, err := io.ReadFull(input, header[:]); err != nil {
		return nodeRuntimeBinaryState{}, err
	}
	hash := sha256.New()
	hash.Write(header[:])
	if !bytes.Equal(header[:4], []byte("\x7fELF")) || (header[4] != 1 && header[4] != 2) || (header[5] != 1 && header[5] != 2) || header[6] != 1 {
		return nodeRuntimeBinaryState{status: "invalid"}, nil
	}
	var order binary.ByteOrder = binary.BigEndian
	if header[5] == 1 {
		order = binary.LittleEndian
	}
	if typ := order.Uint16(header[16:18]); typ != 2 && typ != 3 {
		return nodeRuntimeBinaryState{status: "invalid"}, nil
	}
	if order.Uint16(header[18:20]) == 0 || order.Uint32(header[20:24]) != 1 {
		return nodeRuntimeBinaryState{status: "invalid"}, nil
	}
	var programOffset uint64
	var programSize, programCount uint16
	headerSize := uint64(52)
	wantProgramSize := uint16(32)
	if header[4] == 2 {
		if order.Uint16(header[52:54]) != 64 {
			return nodeRuntimeBinaryState{status: "invalid"}, nil
		}
		headerSize = 64
		wantProgramSize = 56
		programOffset = order.Uint64(header[32:40])
		programSize, programCount = order.Uint16(header[54:56]), order.Uint16(header[56:58])
	} else {
		if order.Uint16(header[40:42]) != 52 {
			return nodeRuntimeBinaryState{status: "invalid"}, nil
		}
		programOffset = uint64(order.Uint32(header[28:32]))
		programSize, programCount = order.Uint16(header[42:44]), order.Uint16(header[44:46])
	}
	if programOffset < headerSize || programOffset > uint64(size) || programSize != wantProgramSize || programCount == 0 || uint64(programSize)*uint64(programCount) > uint64(size)-programOffset {
		return nodeRuntimeBinaryState{status: "invalid"}, nil
	}
	var version string
	var offset int64 = -1
	const overlap = 64
	window := make([]byte, 0, 64<<10+overlap)
	window = append(window, header[:]...)
	buffer := make([]byte, 64<<10)
	consumed := int64(len(header))
	for {
		base := consumed - int64(len(window))
		for _, match := range nodeEmbeddedVersion.FindAllSubmatchIndex(window, -1) {
			candidate := string(window[match[2]:match[3]])
			if version != "" && candidate != version {
				return nodeRuntimeBinaryState{status: "invalid"}, nil
			}
			version = candidate
			if offset < 0 {
				offset = base + int64(match[0]) + 1
			}
		}
		if consumed == size {
			break
		}
		keep := min(len(window), overlap)
		copy(buffer[:keep], window[len(window)-keep:])
		n := int(min(int64(len(buffer)-keep), size-consumed))
		if _, err := io.ReadFull(input, buffer[keep:keep+n]); err != nil {
			return nodeRuntimeBinaryState{}, err
		}
		hash.Write(buffer[keep : keep+n])
		consumed += int64(n)
		window = buffer[:keep+n]
	}
	if version == "" {
		return nodeRuntimeBinaryState{status: "version_unavailable"}, nil
	}
	if !validNodeVersion(version) {
		return nodeRuntimeBinaryState{status: "invalid"}, nil
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	return nodeRuntimeBinaryState{
		version: version, digest: digest,
		evidence: model.Evidence{Collector: "node-runtime-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.FormatInt(offset, 10), Method: "embedded-runtime-version"},
	}, nil
}

func inspectNodeRuntimeHeader(data []byte, source string) nodeRuntimeHeaderState {
	if len(data) == 0 || len(data) > maxNodeHeaderBytes {
		return nodeRuntimeHeaderState{status: "header_invalid"}
	}
	releases := nodeHeaderRelease.FindAllSubmatch(data, -1)
	if len(releases) != 1 || string(releases[0][1]) != "1" {
		return nodeRuntimeHeaderState{status: "header_invalid"}
	}
	parts := map[string]string{}
	for _, match := range nodeHeaderVersion.FindAllSubmatch(data, -1) {
		key, value := string(match[1]), string(match[2])
		if _, duplicate := parts[key]; duplicate {
			return nodeRuntimeHeaderState{status: "header_invalid"}
		}
		parts[key] = value
	}
	if len(parts) != 3 {
		return nodeRuntimeHeaderState{status: "header_invalid"}
	}
	version := parts["MAJOR"] + "." + parts["MINOR"] + "." + parts["PATCH"]
	if !validNodeVersion(version) {
		return nodeRuntimeHeaderState{status: "header_invalid"}
	}
	hash := sha256.Sum256(data)
	return nodeRuntimeHeaderState{version: version, evidence: model.Evidence{Collector: "node-version-header", InputPath: source, InputDigest: "sha256:" + hex.EncodeToString(hash[:]), Pointer: "NODE_*_VERSION", Method: "installed-runtime-header"}}
}

func validNodeVersion(version string) bool {
	for _, part := range strings.Split(version, ".") {
		if len(part) == 0 || len(part) > 3 || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return false
			}
		}
		value, err := strconv.Atoi(part)
		if err != nil || value > 999 {
			return false
		}
	}
	return strings.Count(version, ".") == 2
}

func nodeRuntimeDocument(binaryState nodeRuntimeBinaryState, headerState *nodeRuntimeHeaderState, project string) (model.Document, error) {
	if binaryState.status != "" || binaryState.version == "" || !validNodeVersion(binaryState.version) {
		return model.Document{}, errors.New("invalid Node runtime version")
	}
	if headerState != nil && headerState.status == "" && headerState.version != binaryState.version {
		return model.Document{}, fmt.Errorf("Node runtime binary and installed header versions disagree: %s != %s", binaryState.version, headerState.version)
	}
	evidence := []model.Evidence{binaryState.evidence}
	if headerState != nil && headerState.status == "" {
		evidence = append(evidence, headerState.evidence)
	}
	doc := common.NewDocument(binaryState.evidence.InputPath, project, "node-runtime", nil)
	id := "node-runtime:" + common.ID(binaryState.evidence.InputPath+"\x00"+binaryState.version)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: "node", Version: binaryState.version, Context: "location=/" + nodeRuntimeBinaryPath + ";runtime=nodejs", Hashes: []model.Hash{{Alg: "SHA-256", Content: binaryState.digest}}, Evidence: evidence})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: binaryState.evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_runtime_graph_unavailable", Name: nodeRuntimeBinaryPath}, model.Issue{Code: "node_runtime_origin_unavailable", Name: nodeRuntimeBinaryPath})
	common.Finalize(&doc)
	return doc, nil
}
