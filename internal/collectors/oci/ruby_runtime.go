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

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const (
	maxRubyRuntimeBytes      = 32 << 20
	maxRubyRuntimeLayerBytes = 128 << 20
	maxRubyRuntimeFiles      = 100
	maxRubyDynamicSection    = 8 << 20
)

var rubyRuntimeLibraryName = regexp.MustCompile(`^libruby\.so\.([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,3})$`)

type rubyRuntimeState struct {
	document model.Document
	status   string
}

func isRubyRuntimeLibraryPath(name string) bool {
	return path.Dir(name) == "usr/local/lib" && rubyRuntimeLibraryName.MatchString(path.Base(name))
}

// inspectRubyRuntimeLibrary reads the exported ruby_version object from an
// installed ELF shared library. It does not execute code from the image.
func inspectRubyRuntimeLibrary(data []byte, source, project, filename, architecture string) (document model.Document, err error) {
	if len(data) == 0 || len(data) > maxRubyRuntimeBytes || !isRubyRuntimeLibraryPath(filename) {
		return model.Document{}, errors.New("invalid Ruby runtime library path or size")
	}
	if err := guardELFMetadata(data); err != nil {
		return model.Document{}, err
	}
	defer func() {
		if recover() != nil {
			document = model.Document{}
			err = errors.New("malformed Ruby runtime ELF")
		}
	}()
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || file.Type != elf.ET_DYN || architecture == "amd64" && file.Machine != elf.EM_X86_64 || architecture == "arm64" && file.Machine != elf.EM_AARCH64 || architecture != "amd64" && architecture != "arm64" {
		return model.Document{}, errors.New("invalid Ruby runtime ELF")
	}
	for _, section := range file.Sections {
		if section.Type != elf.SHT_DYNSYM {
			continue
		}
		if section.Size > maxRubyDynamicSection || section.Flags&elf.SHF_COMPRESSED != 0 || section.Link >= uint32(len(file.Sections)) || !tableWithinFile(section.Offset, 1, section.Size, len(data)) {
			return model.Document{}, errors.New("Ruby runtime ELF dynamic symbols are unsafe")
		}
		stringsSection := file.Sections[section.Link]
		if stringsSection.Type != elf.SHT_STRTAB || stringsSection.Size > maxRubyDynamicSection || stringsSection.Flags&elf.SHF_COMPRESSED != 0 || !tableWithinFile(stringsSection.Offset, 1, stringsSection.Size, len(data)) {
			return model.Document{}, errors.New("Ruby runtime ELF dynamic strings are unsafe")
		}
	}
	symbols, err := file.DynamicSymbols()
	if err != nil || len(symbols) > 50000 {
		return model.Document{}, errors.New("Ruby runtime ELF dynamic symbols are unavailable")
	}
	version := rubyRuntimeLibraryName.FindStringSubmatch(path.Base(filename))
	want := version[1] + "." + version[2] + "." + version[3]
	versionOffset := -1
	for _, symbol := range symbols {
		if symbol.Name != "ruby_version" {
			continue
		}
		if versionOffset >= 0 || elf.ST_TYPE(symbol.Info) != elf.STT_OBJECT || symbol.Section == elf.SHN_UNDEF || int(symbol.Section) >= len(file.Sections) || symbol.Size != uint64(len(want)+1) {
			return model.Document{}, errors.New("Ruby runtime version symbol is ambiguous or invalid")
		}
		section := file.Sections[symbol.Section]
		if section.Type != elf.SHT_PROGBITS || symbol.Value < section.Addr || symbol.Value-section.Addr > section.Size || symbol.Size > section.Size-(symbol.Value-section.Addr) {
			return model.Document{}, errors.New("Ruby runtime version symbol points outside data")
		}
		delta := symbol.Value - section.Addr
		if section.Offset > uint64(len(data)) || delta > uint64(len(data))-section.Offset || symbol.Size > uint64(len(data))-section.Offset-delta {
			return model.Document{}, errors.New("Ruby runtime version symbol points outside file")
		}
		offset := section.Offset + delta
		if !bytes.Equal(data[offset:offset+symbol.Size], []byte(want+"\x00")) {
			return model.Document{}, errors.New("Ruby runtime version symbol contradicts filename")
		}
		versionOffset = int(offset)
	}
	if versionOffset < 0 {
		return model.Document{}, errors.New("Ruby runtime version symbol is missing")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "ruby-runtime-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.Itoa(versionOffset), Method: "exported-runtime-version-symbol"}
	doc := common.NewDocument(source, project, "ruby-runtime", nil)
	id := "ruby-runtime:" + common.ID(source+"\x00"+want)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: "ruby", Version: want, Context: "location=/" + filename + ";runtime=cruby", Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_runtime_graph_unavailable", Name: filename}, model.Issue{Code: "ruby_runtime_origin_unavailable", Name: filename})
	common.Finalize(&doc)
	return doc, nil
}
