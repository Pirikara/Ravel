package oci

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"errors"
	goversion "go/version"
	"path"
	"strconv"
	"strings"

	"golang.org/x/mod/module"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const (
	maxGoBinaryBytes      = 64 << 20
	maxGoBinaryLayerBytes = 512 << 20
	maxGoBinaryFiles      = 1000
	maxGoBinaryImageFiles = 10000
	maxGoBinaryModules    = 2000
	maxELFSectionNames    = 2 << 20
)

type goBinaryState struct {
	document model.Document
	status   string
}

var errGoBinaryModuleLimit = errors.New("Go binary contains too many module records")

// inspectGoBinary reads module identities embedded by the Go linker. It is
// deliberately restricted to ELF: the OCI scanner currently targets Linux
// executables and checks the ELF tables before invoking debug/buildinfo.
func inspectGoBinary(data []byte, source, project, binaryPath string) (document model.Document, recognized bool, err error) {
	if len(data) == 0 || len(data) > maxGoBinaryBytes {
		return model.Document{}, false, errors.New("Go binary exceeds size limit")
	}
	if !bytes.Contains(data, []byte("\xff Go buildinf:")) {
		return model.Document{}, false, nil // Ordinary ELF executable.
	}
	if err := guardELFMetadata(data); err != nil {
		return model.Document{}, false, err
	}
	defer func() {
		if recover() != nil {
			document = model.Document{}
			recognized = false
			err = errors.New("malformed Go binary")
		}
	}()
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return model.Document{}, false, errors.New("unreadable Go build information")
	}
	if len(info.Deps) > maxGoBinaryModules {
		return model.Document{}, false, errGoBinaryModuleLimit
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "go-buildinfo", InputPath: source, InputDigest: "sha256:" + digest, Method: "embedded-build-info"}
	doc := common.NewDocument(source, project, "go-binary", nil)
	outerID := "go-binary:" + common.ID(source+"\x00"+digest)
	outerVersion := ""
	if module.Check(info.Main.Path, info.Main.Version) == nil {
		outerVersion = info.Main.Version
	}
	context := "location=/" + binaryPath
	if info.Main.Path != "" && len(info.Main.Path) <= 255 && module.CheckPath(info.Main.Path) == nil {
		context += ";main_module=" + info.Main.Path
	}
	doc.Components = append(doc.Components, model.Component{ID: outerID, Kind: "application", Name: path.Base(binaryPath), Version: outerVersion, Context: context, Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: outerID, Kind: "installed", Evidence: evidence})
	goVersion := strings.Fields(info.GoVersion)
	version := ""
	if len(goVersion) > 0 {
		version = strings.SplitN(goVersion[0], "-X:", 2)[0]
	}
	if len(version) <= 64 && goversion.IsValid(version) {
		stdlibID := "go-binary:" + common.ID(source+"\x00stdlib\x00"+version)
		stdlibEvidence := evidence
		stdlibEvidence.Pointer = "buildinfo/goVersion"
		doc.Components = append(doc.Components, model.Component{ID: stdlibID, Kind: "package", Name: "stdlib", Version: version, Context: "binary=/" + binaryPath, Evidence: []model.Evidence{stdlibEvidence}})
		doc.Edges = append(doc.Edges, model.Edge{From: outerID, To: stdlibID, Kind: "embedded", Evidence: stdlibEvidence})
	} else {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "go_binary_toolchain_unparsed", Name: binaryPath})
	}
	seen := map[string]bool{}
	for i, item := range info.Deps {
		if item == nil {
			continue
		}
		selected := item
		pointer := "buildinfo/deps/" + strconv.Itoa(i)
		moduleContext := "binary=/" + binaryPath
		if item.Replace != nil {
			selected = item.Replace
			pointer += "/replace"
			if item.Replace.Version == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "go_binary_local_replacement_unresolved", Name: binaryPath})
				continue
			}
			if module.CheckPath(item.Path) == nil && len(item.Path) <= 255 && len(item.Version) <= 128 {
				moduleContext += ";replaces=" + item.Path + "@" + item.Version
			}
		}
		if len(selected.Path) > 255 || len(selected.Version) > 128 || module.Check(selected.Path, selected.Version) != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "go_binary_module_unparsed", Name: binaryPath})
			continue
		}
		key := selected.Path + "\x00" + selected.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		componentID := "go-binary:" + common.ID(source+"\x00"+key)
		moduleEvidence := evidence
		moduleEvidence.Pointer = pointer
		purl := ""
		if item.Replace == nil {
			purl = common.GoModulePURL(selected.Path, selected.Version)
		}
		doc.Components = append(doc.Components, model.Component{ID: componentID, Kind: "package", Name: selected.Path, Version: selected.Version, Context: moduleContext, PURL: purl, Evidence: []model.Evidence{moduleEvidence}})
		doc.Edges = append(doc.Edges, model.Edge{From: outerID, To: componentID, Kind: "embedded", Evidence: moduleEvidence})
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "go_binary_graph_unavailable", Name: binaryPath}, model.Issue{Code: "go_binary_origin_unavailable", Name: binaryPath})
	common.Finalize(&doc)
	return doc, true, nil
}

// guardELFMetadata bounds the ELF tables and section-name string table that
// debug/elf reads eagerly. Compressed section-name tables are rejected before
// debug/buildinfo can inflate attacker-controlled declared sizes.
func guardELFMetadata(data []byte) error {
	if len(data) < 52 || !bytes.HasPrefix(data, []byte("\x7fELF")) {
		return errors.New("invalid ELF header")
	}
	var order binary.ByteOrder
	switch data[5] {
	case 1:
		order = binary.LittleEndian
	case 2:
		order = binary.BigEndian
	default:
		return errors.New("unsupported ELF byte order")
	}
	var phoff, shoff uint64
	var phentsize, phnum, shentsize, shnum, shstrndx uint16
	var minProgramHeader, minSectionHeader uint16
	switch data[4] {
	case 1: // ELF32
		phoff = uint64(order.Uint32(data[28:32]))
		shoff = uint64(order.Uint32(data[32:36]))
		phentsize, phnum = order.Uint16(data[42:44]), order.Uint16(data[44:46])
		shentsize, shnum, shstrndx = order.Uint16(data[46:48]), order.Uint16(data[48:50]), order.Uint16(data[50:52])
		minProgramHeader, minSectionHeader = 32, 40
	case 2: // ELF64
		if len(data) < 64 {
			return errors.New("truncated ELF64 header")
		}
		phoff = order.Uint64(data[32:40])
		shoff = order.Uint64(data[40:48])
		phentsize, phnum = order.Uint16(data[54:56]), order.Uint16(data[56:58])
		shentsize, shnum, shstrndx = order.Uint16(data[58:60]), order.Uint16(data[60:62]), order.Uint16(data[62:64])
		minProgramHeader, minSectionHeader = 56, 64
	default:
		return errors.New("unsupported ELF class")
	}
	if phnum == 0xffff || shstrndx == 0xffff || phnum > 4096 || shnum > 8192 {
		return errors.New("ELF header count exceeds supported limit")
	}
	if phnum > 0 && (phentsize < minProgramHeader || !tableWithinFile(phoff, uint64(phentsize), uint64(phnum), len(data))) {
		return errors.New("invalid ELF program headers")
	}
	if shnum == 0 && shoff == 0 {
		return nil // Sectionless ELF can still carry Go build info in a segment.
	}
	if shnum == 0 || shentsize < minSectionHeader || !tableWithinFile(shoff, uint64(shentsize), uint64(shnum), len(data)) {
		return errors.New("invalid ELF section headers")
	}
	if shstrndx == 0 {
		return nil
	}
	if shstrndx >= shnum {
		return errors.New("invalid ELF section-name index")
	}
	section := data[shoff+uint64(shstrndx)*uint64(shentsize):]
	var flags, offset, size uint64
	if data[4] == 1 {
		flags = uint64(order.Uint32(section[8:12]))
		offset = uint64(order.Uint32(section[16:20]))
		size = uint64(order.Uint32(section[20:24]))
	} else {
		flags = order.Uint64(section[8:16])
		offset = order.Uint64(section[24:32])
		size = order.Uint64(section[32:40])
	}
	if flags&0x800 != 0 || size > maxELFSectionNames || !tableWithinFile(offset, 1, size, len(data)) {
		return errors.New("ELF section-name table is compressed, oversized, or invalid")
	}
	return nil
}

func tableWithinFile(offset, entrySize, count uint64, length int) bool {
	return offset <= uint64(length) && entrySize <= uint64(length) && count <= (uint64(length)-offset)/entrySize
}

func isELFMagic(data []byte) bool {
	return bytes.Equal(data, []byte("\x7fELF"))
}
