package oci

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const (
	phpCLIBinaryPath  = "usr/local/bin/php"
	maxPHPBinaryBytes = 64 << 20
)

const php8VersionExpression = `8\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})`

var (
	phpPoweredByPattern = regexp.MustCompile(`\x00X-Powered-By: PHP/(` + php8VersionExpression + `)\x00`)
	phpMySQLNDPattern   = regexp.MustCompile(`\x00mysqlnd (` + php8VersionExpression + `)\x00`)
	phpZendPattern      = regexp.MustCompile(`\x00Zend Engine v(4\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})), Copyright`)
)

type phpCLIBinaryState struct {
	document model.Document
	status   string
}

// inspectPHPCLIBinary identifies a source-installed PHP 8 CLI executable
// using its PHP and Zend Engine versions and the CLI output template.
func inspectPHPCLIBinary(data []byte, source, project, architecture string) (model.Document, error) {
	return inspectPHPBinary(data, source, project, architecture, "php-cli", phpCLIBinaryPath, phpCLIVersionInROData)
}

func inspectPHPBinary(data []byte, source, project, architecture, runtime, filename string, versionInROData func([]byte) (string, int, bool)) (document model.Document, err error) {
	if len(data) < 64 || len(data) > maxPHPBinaryBytes {
		return model.Document{}, errors.New("invalid PHP executable size")
	}
	if err := guardELFMetadata(data); err != nil {
		return model.Document{}, err
	}
	defer func() {
		if recover() != nil {
			document = model.Document{}
			err = errors.New("malformed PHP ELF")
		}
	}()
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return model.Document{}, errors.New("invalid PHP ELF")
	}
	if architecture != "arm64" && architecture != "amd64" || architecture == "arm64" && file.Machine != elf.EM_AARCH64 || architecture == "amd64" && file.Machine != elf.EM_X86_64 {
		return model.Document{}, errors.New("PHP ELF architecture does not match image")
	}
	section := file.Section(".rodata")
	if section == nil || section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_ALLOC == 0 || section.Flags&(elf.SHF_WRITE|elf.SHF_COMPRESSED) != 0 || section.Offset > uint64(len(data)) || section.Size > uint64(len(data))-section.Offset {
		return model.Document{}, errors.New("PHP read-only data is unavailable")
	}
	version, offset, ok := versionInROData(data[section.Offset : section.Offset+section.Size])
	if !ok {
		return model.Document{}, errors.New("PHP executable version is unavailable or ambiguous")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: runtime + "-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.FormatUint(section.Offset+uint64(offset), 10), Method: "embedded-runtime-version"}
	doc := common.NewDocument(source, project, runtime, nil)
	id := runtime + ":" + common.ID(source+"\x00"+version)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "application", Name: runtime, Version: version, Context: "location=/" + filename + ";runtime=" + runtime, Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	issuePrefix := strings.ReplaceAll(runtime, "-", "_")
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: issuePrefix + "_graph_unavailable", Name: filename}, model.Issue{Code: issuePrefix + "_origin_unavailable", Name: filename})
	common.Finalize(&doc)
	return doc, nil
}

func phpCLIVersionInROData(data []byte) (string, int, bool) {
	if !bytes.Contains(data, []byte("\x00PHP %s (%s) (built: %s %s) (%s)\nCopyright (c) The PHP Group\n")) {
		return "", -1, false
	}
	return php8VersionInROData(data)
}

func php8VersionInROData(data []byte) (string, int, bool) {
	powered := phpPoweredByPattern.FindAllSubmatchIndex(data, 9)
	zend := phpZendPattern.FindAllSubmatchIndex(data, 9)
	if len(powered) == 0 || len(powered) > 8 || len(zend) == 0 || len(zend) > 8 {
		return "", -1, false
	}
	version, offset := "", -1
	for _, match := range powered {
		candidate := string(data[match[2]:match[3]])
		if version != "" && candidate != version {
			return "", -1, false
		}
		version, offset = candidate, match[2]
	}
	wantZend := "4." + strings.TrimPrefix(version, "8.")
	for _, match := range zend {
		if string(data[match[2]:match[3]]) != wantZend {
			return "", -1, false
		}
	}
	mysqlnd := phpMySQLNDPattern.FindAllSubmatchIndex(data, 9)
	if len(mysqlnd) > 8 {
		return "", -1, false
	}
	for _, match := range mysqlnd {
		if string(data[match[2]:match[3]]) != version {
			return "", -1, false
		}
	}
	return version, offset, true
}
