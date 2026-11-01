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
	httpdBinaryPath     = "usr/local/apache2/bin/httpd"
	maxHTTPDBinaryBytes = 32 << 20
)

const httpdVersionExpression = `[1-9][0-9]{0,2}\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})`

var (
	httpdFullVersionPattern  = regexp.MustCompile(`\x00Apache/(` + httpdVersionExpression + `) \(Unix\)\x00`)
	httpdShortVersionPattern = regexp.MustCompile(`\x00Apache/(` + httpdVersionExpression + `)\x00`)
)

type httpdBinaryState struct {
	document model.Document
	status   string
}

// inspectHTTPDBinary identifies the source-installed Apache server from the
// final executable's two version strings and its own version output template.
func inspectHTTPDBinary(data []byte, source, project, architecture string) (document model.Document, err error) {
	if len(data) < 64 || len(data) > maxHTTPDBinaryBytes {
		return model.Document{}, errors.New("invalid httpd executable size")
	}
	if err := guardELFMetadata(data); err != nil {
		return model.Document{}, err
	}
	defer func() {
		if recover() != nil {
			document = model.Document{}
			err = errors.New("malformed httpd ELF")
		}
	}()
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return model.Document{}, errors.New("invalid httpd ELF")
	}
	if architecture != "arm64" && architecture != "amd64" || architecture == "arm64" && file.Machine != elf.EM_AARCH64 || architecture == "amd64" && file.Machine != elf.EM_X86_64 {
		return model.Document{}, errors.New("httpd ELF architecture does not match image")
	}
	section := file.Section(".rodata")
	if section == nil || section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_ALLOC == 0 || section.Flags&(elf.SHF_WRITE|elf.SHF_COMPRESSED) != 0 || section.Offset > uint64(len(data)) || section.Size > uint64(len(data))-section.Offset {
		return model.Document{}, errors.New("httpd read-only data is unavailable")
	}
	version, offset, ok := httpdVersionInROData(data[section.Offset : section.Offset+section.Size])
	if !ok {
		return model.Document{}, errors.New("httpd executable version is unavailable or ambiguous")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "httpd-server-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.FormatUint(section.Offset+uint64(offset), 10), Method: "embedded-server-version"}
	doc := common.NewDocument(source, project, "httpd-server", nil)
	id := "httpd-server:" + common.ID(source+"\x00"+version)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "application", Name: "httpd", Version: version, Context: "location=/" + httpdBinaryPath + ";server=httpd", Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "httpd_server_graph_unavailable", Name: httpdBinaryPath}, model.Issue{Code: "httpd_server_origin_unavailable", Name: httpdBinaryPath})
	common.Finalize(&doc)
	return doc, nil
}

func httpdVersionInROData(data []byte) (string, int, bool) {
	if !bytes.Contains(data, []byte("\x00Server version: %s\n\x00")) {
		return "", -1, false
	}
	fullMatches := httpdFullVersionPattern.FindAllSubmatchIndex(data, 9)
	shortMatches := httpdShortVersionPattern.FindAllSubmatchIndex(data, 9)
	if len(fullMatches) == 0 || len(fullMatches) > 8 || len(shortMatches) == 0 || len(shortMatches) > 8 {
		return "", -1, false
	}
	version, offset := "", -1
	for _, match := range fullMatches {
		candidate := string(data[match[2]:match[3]])
		if version != "" && candidate != version {
			return "", -1, false
		}
		version, offset = candidate, match[2]
	}
	nearby := false
	for _, match := range shortMatches {
		if string(data[match[2]:match[3]]) != version {
			return "", -1, false
		}
		for _, full := range fullMatches {
			distance := full[2] - match[2]
			if distance < 0 {
				distance = -distance
			}
			if distance <= 512 {
				nearby = true
			}
		}
	}
	if !nearby {
		return "", -1, false
	}
	return version, offset, true
}
