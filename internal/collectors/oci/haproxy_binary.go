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
	haproxyBinaryPath     = "usr/local/sbin/haproxy"
	maxHAProxyBinaryBytes = 64 << 20
)

const haproxyVersionExpression = `[1-9][0-9]{0,2}\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})`

var (
	haproxyBuildPattern     = regexp.MustCompile(`\x00(` + haproxyVersionExpression + `)-([0-9a-f]{7})\x00{1,8}haproxy_server_`)
	haproxyBenchmarkPattern = regexp.MustCompile(`\x00HAProxy's dummy HTTP server for benchmarks - version (` + haproxyVersionExpression + `)-([0-9a-f]{7})\.`)
)

type haproxyBinaryState struct {
	document model.Document
	status   string
}

// inspectHAProxyBinary identifies a source-installed server from two
// matching version and revision strings in the final executable.
func inspectHAProxyBinary(data []byte, source, project, architecture string) (document model.Document, err error) {
	if len(data) < 64 || len(data) > maxHAProxyBinaryBytes {
		return model.Document{}, errors.New("invalid HAProxy executable size")
	}
	if err := guardELFMetadata(data); err != nil {
		return model.Document{}, err
	}
	defer func() {
		if recover() != nil {
			document = model.Document{}
			err = errors.New("malformed HAProxy ELF")
		}
	}()
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return model.Document{}, errors.New("invalid HAProxy ELF")
	}
	if architecture != "arm64" && architecture != "amd64" || architecture == "arm64" && file.Machine != elf.EM_AARCH64 || architecture == "amd64" && file.Machine != elf.EM_X86_64 {
		return model.Document{}, errors.New("HAProxy ELF architecture does not match image")
	}
	section := file.Section(".rodata")
	if section == nil || section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_ALLOC == 0 || section.Flags&(elf.SHF_WRITE|elf.SHF_COMPRESSED) != 0 || section.Offset > uint64(len(data)) || section.Size > uint64(len(data))-section.Offset {
		return model.Document{}, errors.New("HAProxy read-only data is unavailable")
	}
	version, revision, offset, ok := haproxyVersionInROData(data[section.Offset : section.Offset+section.Size])
	if !ok {
		return model.Document{}, errors.New("HAProxy executable version is unavailable or ambiguous")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "haproxy-server-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.FormatUint(section.Offset+uint64(offset), 10), Method: "embedded-server-version"}
	doc := common.NewDocument(source, project, "haproxy-server", nil)
	id := "haproxy-server:" + common.ID(source+"\x00"+version+"\x00"+revision)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "application", Name: "haproxy", Version: version, Context: "location=/" + haproxyBinaryPath + ";server=haproxy;revision=" + revision, Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "haproxy_server_graph_unavailable", Name: haproxyBinaryPath}, model.Issue{Code: "haproxy_server_origin_unavailable", Name: haproxyBinaryPath})
	common.Finalize(&doc)
	return doc, nil
}

func haproxyVersionInROData(data []byte) (string, string, int, bool) {
	if !bytes.Contains(data, []byte("\x00HAProxy version %s %s - https://haproxy.org/\n")) {
		return "", "", -1, false
	}
	builds := haproxyBuildPattern.FindAllSubmatchIndex(data, 9)
	benchmarks := haproxyBenchmarkPattern.FindAllSubmatchIndex(data, 9)
	if len(builds) == 0 || len(builds) > 8 || len(benchmarks) == 0 || len(benchmarks) > 8 {
		return "", "", -1, false
	}
	version, revision, offset := "", "", -1
	for _, match := range builds {
		candidate, commit := string(data[match[2]:match[3]]), string(data[match[4]:match[5]])
		if version != "" && (candidate != version || commit != revision) {
			return "", "", -1, false
		}
		version, revision, offset = candidate, commit, match[2]
	}
	for _, match := range benchmarks {
		if string(data[match[2]:match[3]]) != version || string(data[match[4]:match[5]]) != revision {
			return "", "", -1, false
		}
	}
	return version, revision, offset, true
}
