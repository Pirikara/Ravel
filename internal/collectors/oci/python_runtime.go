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

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const (
	maxPythonRuntimeBytes      = 32 << 20
	maxPythonRuntimeLayerBytes = 128 << 20
	maxPythonRuntimeFiles      = 100
)

var pythonRuntimeLibraryName = regexp.MustCompile(`^libpython(3)\.([0-9]{1,2})\.so(?:\.[0-9]+){0,2}$`)

type pythonRuntimeState struct {
	document model.Document
	status   string
}

func isPythonRuntimeLibraryPath(name string) bool {
	return path.Dir(name) == "usr/local/lib" && pythonRuntimeLibraryName.MatchString(path.Base(name))
}

// inspectPythonRuntimeLibrary identifies an installed CPython shared library
// from its ELF format, public API symbol, and an embedded version that agrees
// with the library filename. It does not execute code from the image.
func inspectPythonRuntimeLibrary(data []byte, source, project, filename string) (document model.Document, recognized bool, err error) {
	if len(data) == 0 || len(data) > maxPythonRuntimeBytes || !isPythonRuntimeLibraryPath(filename) {
		return model.Document{}, false, errors.New("invalid Python runtime library path or size")
	}
	if err := guardELFMetadata(data); err != nil {
		return model.Document{}, false, err
	}
	defer func() {
		if recover() != nil {
			document = model.Document{}
			recognized = false
			err = errors.New("malformed Python runtime ELF")
		}
	}()
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || file.Type != elf.ET_DYN {
		return model.Document{}, false, errors.New("invalid Python runtime ELF")
	}
	if !bytes.Contains(data, []byte("Py_GetVersion\x00")) {
		return model.Document{}, false, errors.New("Python runtime version symbol is missing")
	}
	parts := pythonRuntimeLibraryName.FindStringSubmatch(path.Base(filename))
	prefix := []byte("\x00" + parts[1] + "." + parts[2] + ".")
	version := ""
	versionOffset := -1
	for position := 0; position < len(data); {
		index := bytes.Index(data[position:], prefix)
		if index < 0 {
			break
		}
		start := position + index
		patchStart := start + len(prefix)
		patchEnd := patchStart
		for patchEnd < len(data) && patchEnd-patchStart < 4 && data[patchEnd] >= '0' && data[patchEnd] <= '9' {
			patchEnd++
		}
		if patchEnd > patchStart && patchEnd-patchStart <= 3 && patchEnd < len(data) && data[patchEnd] == 0 {
			candidate := parts[1] + "." + parts[2] + "." + string(data[patchStart:patchEnd])
			if version != "" && version != candidate {
				return model.Document{}, false, errors.New("ambiguous Python runtime version")
			}
			version = candidate
			versionOffset = start + 1
		}
		position = start + len(prefix)
	}
	if version == "" {
		return model.Document{}, false, errors.New("Python runtime version is unavailable")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "python-runtime-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/offset/" + strconv.Itoa(versionOffset), Method: "embedded-runtime-version"}
	doc := common.NewDocument(source, project, "python-runtime", nil)
	id := "python-runtime:" + common.ID(source+"\x00"+version)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: "python", Version: version, Context: "location=/" + filename + ";runtime=cpython", Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "python_runtime_graph_unavailable", Name: filename}, model.Issue{Code: "python_runtime_origin_unavailable", Name: filename})
	common.Finalize(&doc)
	return doc, true, nil
}
